package database

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/errwrap"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/vault/builtin/logical/database/dbplugin"
	"github.com/hashicorp/vault/helper/queue"
	"github.com/hashicorp/vault/helper/strutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/mitchellh/mapstructure"
)

// rotateCredentials sets a new password for a static account. This method is
// invoked by a go-routine launched the runTicker method, and invoked
// periodically (approximately every 5 seconds).
// This will loop until either:
// - The queue of passwords needing rotation is completely empty.
// - It encounters the first password not yet needing rotation.
func (b *databaseBackend) rotateCredentials(ctx context.Context, s logical.Storage) error {
	for {
		item, err := b.credRotationQueue.PopItem()
		if err != nil {
			if err == queue.ErrEmpty {
				return nil
			}
			return err
		}

		role, err := b.Role(ctx, s, item.Key)
		if err != nil {
			b.logger.Warn(fmt.Sprintf("unable load role (%s)", item.Key), "error", err)
			continue
		}
		if role == nil {
			b.logger.Warn(fmt.Sprintf("role (%s) not found", item.Key), "error", err)
			continue
		}

		if time.Now().Unix() > item.Priority {
			// We've found our first item not in need of rotation
			input := &setPasswordInput{
				RoleName: item.Key,
				Role:     role,
			}

			// check for existing WAL entry with a Password
			if walID, ok := item.Value.(string); ok {
				walEntry := b.walForItemValue(ctx, s, walID)
				if walEntry != nil && walEntry.NewPassword != "" {
					input.Password = walEntry.NewPassword
					input.WALID = walID
				}
			}

			// lvr is the roles' last vault rotation
			resp, err := b.createUpdateStaticAccount(ctx, s, input)
			if err != nil {
				b.logger.Warn("unable rotate credentials in periodic function", "error", err)
				// add the item to the re-queue slice
				newItem := queue.Item{
					Key:      item.Key,
					Priority: item.Priority + 10,
				}

				// preserve the WALID if it was returned
				if resp.WALID != "" {
					newItem.Value = resp.WALID
				}

				if err := b.credRotationQueue.PushItem(&newItem); err != nil {
					b.logger.Warn("unable to push item on to queue", "error", err)
				}
				// go to next item
				continue
			}

			// guard against RotationTime not being set or zero-value
			lvr := resp.RotationTime
			if lvr.IsZero() {
				lvr = time.Now()
			}

			nextRotation := lvr.Add(role.StaticAccount.RotationPeriod)
			newItem := queue.Item{
				Key:      item.Key,
				Priority: nextRotation.Unix(),
			}
			if err := b.credRotationQueue.PushItem(&newItem); err != nil {
				b.logger.Warn("unable to push item on to queue", "error", err)
			}
		} else {
			// highest priority item does not need rotation, so we push it back on
			// the queue and break the loop
			b.credRotationQueue.PushItem(item)
			break
		}
	}
	return nil
}

func (b *databaseBackend) walForItemValue(ctx context.Context, s logical.Storage, id string) *walSetCredentials {
	// TODO: use and return multi-error here
	wal, err := framework.GetWAL(ctx, s, id)
	if err != nil {
		b.Logger().Warn(fmt.Sprintf("error reading WAL for ID (%s):", id), err)
		return nil
	}

	if wal == nil || wal.Kind != walRotationKey {
		return nil
	}

	var walEntry walSetCredentials
	if mapErr := mapstructure.Decode(wal.Data, &walEntry); err != nil {
		b.Logger().Warn("error decoding walEntry", mapErr.Error())
		return nil
	}

	return &walEntry
}

// TODO: rename to match the method these go with
type setPasswordInput struct {
	RoleName   string
	Role       *roleEntry
	Password   string
	CreateUser bool
	WALID      string
}

type setPasswordResponse struct {
	RotationTime time.Time
	// Optional return field, in the event WAL was created and not destroyed
	// during the operation
	WALID string
}

func (b *databaseBackend) createUpdateStaticAccount(ctx context.Context, s logical.Storage, input *setPasswordInput) (*setPasswordResponse, error) {
	var lvr time.Time
	var merr error
	// re-use WAL ID if present, otherwise PUT a new WAL
	setResponse := &setPasswordResponse{WALID: input.WALID}

	dbConfig, err := b.DatabaseConfig(ctx, s, input.Role.DBName)
	if err != nil {
		return setResponse, err
	}

	// If role name isn't in the database's allowed roles, send back a
	// permission denied.
	if !strutil.StrListContains(dbConfig.AllowedRoles, "*") && !strutil.StrListContainsGlob(dbConfig.AllowedRoles, input.RoleName) {
		return setResponse, fmt.Errorf("%q is not an allowed role", input.RoleName)
	}

	// Get the Database object
	db, err := b.GetConnection(ctx, s, input.Role.DBName)
	if err != nil {
		return setResponse, err
	}

	// Use password from input if available. This happens if we're restoring from
	// a WAL item or processing the rotation queue with an item that has a WAL
	// associated with it
	newPassword := input.Password
	if newPassword == "" {
		// Generate a new password
		newPassword, err = db.GenerateCredentials(ctx)
		if err != nil {
			return setResponse, err
		}
	}

	db.RLock()
	defer db.RUnlock()

	config := dbplugin.StaticUserConfig{
		Username: input.Role.StaticAccount.Username,
		Password: newPassword,
	}

	// Create or rotate the user
	stmts := input.Role.Statements.Creation
	if !input.CreateUser {
		stmts = input.Role.Statements.Rotation
	}

	if setResponse.WALID == "" {
		setResponse.WALID, err = framework.PutWAL(ctx, s, walRotationKey, &walSetCredentials{
			RoleName:          input.RoleName,
			Username:          config.Username,
			NewPassword:       config.Password,
			OldPassword:       input.Role.StaticAccount.Password,
			Statements:        stmts,
			LastVaultRotation: input.Role.StaticAccount.LastVaultRotation,
		})
		if err != nil {
			// TODO: error wrap here?
			return setResponse, errwrap.Wrapf("error writing WAL entry: {{err}}", err)
		}
	}

	var sterr error
	_, password, _, sterr := db.SetCredentials(ctx, config, stmts)
	if sterr != nil {
		b.CloseIfShutdown(db, sterr)
		return setResponse, sterr
	}

	// TODO set credentials doesn't need to return all these things
	if newPassword != password {
		return setResponse, errors.New("mismatch password returned")
	}

	// Store updated role information
	lvr = time.Now()
	input.Role.StaticAccount.LastVaultRotation = lvr
	input.Role.StaticAccount.Password = password
	setResponse.RotationTime = lvr

	entry, err := logical.StorageEntryJSON("role/"+input.RoleName, input.Role)
	if err != nil {
		return setResponse, err
	}
	if err := s.Put(ctx, entry); err != nil {
		return setResponse, err
	}

	// cleanup WAL after successfully rotating and pushing new item on to queue
	if err := framework.DeleteWAL(ctx, s, setResponse.WALID); err != nil {
		merr = multierror.Append(merr, err)
	}

	return setResponse, merr
}

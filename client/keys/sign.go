package keys

import (
	"fmt"
	"io/ioutil"

	"github.com/spf13/viper"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/x/auth"
	"github.com/spf13/cobra"
	amino "github.com/tendermint/go-amino"
)

// GetSignCommand returns the sign command
func GetSignCommand(codec *amino.Codec) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sign <file>",
		Short: "Sign transactions",
		Long: `Sign transactions created with the --generate-only flag.
Read a transaction from <file>, sign it, and print the JSON
encoding of the signed transaction to STDOUT.`,
		RunE: makeSignCmd(codec),
		Args: cobra.ExactArgs(1),
	}
	cmd.Flags().String(client.FlagName, "", "Name of private key with which to sign")
	cmd.Flags().String("file", "", "Transaction filename")
	// cmd.Flags().Bool(client.FlagUseLedger, false, "Store a local reference to a private key on a Ledger device")
	// cmd.Flags().Uint32(flagAccount, 0, "Account number for HD derivation")
	// cmd.Flags().Uint32(flagIndex, 0, "Index number for HD derivation")
	return cmd
}

func sign(codec *amino.Codec, key string, msg auth.StdSignMsg) ([]byte, error) {
	keybase, err := GetKeyBase()
	if err != nil {
		return nil, err
	}
	passphrase, err := GetPassphrase(key)
	if err != nil {
		return nil, err
	}
	sig, pubkey, err := keybase.Sign(key, passphrase, msg.Bytes())
	if err != nil {
		return nil, err
	}

	sigs := []auth.StdSignature{{
		AccountNumber: msg.AccountNumber,
		Sequence:      msg.Sequence,
		PubKey:        pubkey,
		Signature:     sig,
	}}

	return codec.MarshalJSON(auth.NewStdTx(msg.Msgs, msg.Fee, sigs, msg.Memo))
}

func makeSignCmd(codec *amino.Codec) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) (err error) {
		bytes, err := ioutil.ReadFile(args[0])
		if err != nil {
			return
		}
		var tx auth.StdSignMsg
		err = codec.UnmarshalJSON(bytes, &tx)
		if err != nil {
			return
		}
		bytes, err = sign(codec, viper.GetString(client.FlagName), tx)
		if err != nil {
			return
		}
		fmt.Printf("%s\n", bytes)
		return
	}
}

package cli

import (
	"fmt"

	"github.com/cosmos/cosmos-sdk/codec"
	codectypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/onsonr/sonr/app/cli/dexmodel"
	"github.com/onsonr/sonr/app/cli/txmodel"
	"github.com/spf13/cobra"
)

func NewBuildTxnTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dash",
		Short: "TUI for managing the local Sonr validator node",
		RunE: func(cmd *cobra.Command, args []string) error {
			txBody, err := txmodel.RunBuildTxnTUI()
			if err != nil {
				return err
			}

			interfaceRegistry := codectypes.NewInterfaceRegistry()
			marshaler := codec.NewProtoCodec(interfaceRegistry)
			jsonBytes, err := marshaler.MarshalJSON(txBody)
			if err != nil {
				return fmt.Errorf("failed to marshal tx body: %w", err)
			}

			fmt.Println("Generated Protobuf Message (JSON format):")
			fmt.Println(string(jsonBytes))

			return nil
		},
	}
}

func NewExplorerTUICmd() *cobra.Command {
	return &cobra.Command{
		Use:   "cosmos-explorer",
		Short: "A terminal-based Cosmos blockchain explorer",
		RunE:  dexmodel.RunExplorerTUI,
	}
}

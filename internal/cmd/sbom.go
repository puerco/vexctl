/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openvex/vexctl/pkg/sbom"
)

type sbomOptions struct {
	outFileOption
	vexDocuments []string
	sbomPath     string
	// documentPath string
}

func (o *sbomOptions) Validate() error {
	var fileError error
	return errors.Join(
		o.outFileOption.Validate(),
		fileError,
	)
}

func (o *sbomOptions) AddFlags(cmd *cobra.Command) {
	// o.vexStatementOptions.AddFlags(cmd)
	o.outFileOption.AddFlags(cmd)

	cmd.PersistentFlags().StringSliceVar(
		&o.vexDocuments,
		"vex",
		[]string{},
		"supplemental OpenVEX documents with applicable statements",
	)

	cmd.PersistentFlags().StringVar(
		&o.sbomPath,
		"sbom",
		"",
		"path to SBOM file (when not in args)",
	)
}

func addSBOM(parentCmd *cobra.Command) {
	opts := sbomOptions{}
	sbomCmd := &cobra.Command{
		Short: fmt.Sprintf("%s sbom: generates an OpenVEX document from an SBOM", appname),
		Long: fmt.Sprintf(`%s sbom: generates an OpenVEX document from an SBOM

The sbom subcommand reads an sbom and generates an OpenVEX document applicable to
the software described in it. vexctl will attempt to discover VEX data for each of
the components or supplemental VEX documents can be provided with VES statements
about the components.

This invocation will output an OpenVEX document with all data found about the
software described in the SBOM:

%s sbom sbom.spdx.json

Both SDPX or CycloneDX formats are supported. 

`, appname, appname),
		Use:               "sbom [flags] sbom-file.json",
		Example:           fmt.Sprintf("%s sbom myproduct.spdx.json", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 || (len(args) == 1) && opts.sbomPath != "" {
				return fmt.Errorf("only one SBOM can be specified at a time")
			}

			if len(args) == 0 && opts.sbomPath == "" {
				return fmt.Errorf("a path to an SBOM file must be specified")
			}

			if len(args) == 1 {
				opts.sbomPath = args[0]
			}

			if err := opts.Validate(); err != nil {
				return err
			}

			handler := sbom.NewHandler()
			doc, err := handler.VexSBOMFile(&sbom.Options{
				VexFiles: opts.vexDocuments,
			}, opts.sbomPath)
			if err != nil {
				return fmt.Errorf("vexing SBOM data: %w", err)
			}

			return writeDocument(doc, opts.outFilePath)
		},
	}

	opts.AddFlags(sbomCmd)
	parentCmd.AddCommand(sbomCmd)
}

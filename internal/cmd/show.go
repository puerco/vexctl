/*
Copyright 2022 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/openvex/vexctl/pkg/ctl"
)

type showOptions struct {
	vulnerabilityListOption
	productsListOption
}

func (o *showOptions) Validate() error {
	if err := o.productsListOption.Validate(); err != nil {
		return err
	}

	if err := o.productsListOption.Validate(); err != nil {
		return err
	}

	return nil
}

func (o *showOptions) AddFlags(cmd *cobra.Command) {
	o.vulnerabilityListOption.AddFlags(cmd)
	o.productsListOption.AddFlags(cmd)
}

func addShow(parentCmd *cobra.Command) {
	opts := showOptions{}
	addCmd := &cobra.Command{
		Short: fmt.Sprintf("%s show: prints a summary of an OpenVEX document", appname),
		Long: fmt.Sprintf(`%s show: prints a summary of an OpenVEX document

The vexctl show subcommand reads a series of OpenVEX documents and prints a
summary of their contents to better visualize the VEX history of vulnerabilities.

The subcommand also supports filtering by product and vulnerability identifiers
to help better isolate a particular history line.

Some examples of vexctl show:

# Show all the data in 
%s show file1.openvex.json file2.openvex.json 

# Show all VEX data about log4j:

%s show --vuln=CVE-2021-44228 file1.openvex.json file2.openvex.json



`, appname, appname, appname),
		Use:               "show [flags] document.spdx.json [document.spdx.json]...",
		Example:           fmt.Sprintf("%s show file.openvex.json", appname),
		SilenceUsage:      false,
		SilenceErrors:     true,
		PersistentPreRunE: initLogging,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return fmt.Errorf("at least one file must be specified when running %s show", appname)
			}
			// If we have arguments, add them
			if err := opts.Validate(); err != nil {
				return err
			}

			doc, err := vex.MergeFiles(args)
			if err != nil {
				return fmt.Errorf("merging files: %w", err)
			}

			ctl.PrintStatusTable(doc.Statements, os.Stdout)
			return nil
		},
	}

	opts.AddFlags(addCmd)
	parentCmd.AddCommand(addCmd)
}

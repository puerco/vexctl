/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package sbom

import (
	"fmt"
	"io"

	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
)

type Handler struct {
	impl   sbomHandlerImplementation
	logger logrus.Logger
}

type Options struct {
	// VexFiles are additional file with VEX data about the components
	VexFiles []string

	// Nodes are identifiers to be added as products in the VEX document. All
	// top level elements will be added if none are defined.
	Nodes []string

	// RunDiscovery is a boolean that controls if vexctl recurses the
	// SBOM components using the discovery module. When running the
	// default discovery, vexctl will look into git repositories to try
	// to find VEX data for each.
	RunDiscovery bool
}

func NewHandler() *Handler {
	return &Handler{
		impl: &defaultHandlerImplementation{},
	}
}

// VexSBOM assembles a new OpenVEX document by incorporating the data
func (h *Handler) VexSBOM(opts *Options, r io.ReadSeeker) (*vex.VEX, error) {
	// Load and parse the SBOM
	bom, err := h.impl.ParseSBOM(r)
	if err != nil {
		return nil, fmt.Errorf("parsing SBOM: %w", err)
	}

	// Get the node graph fragments from the SBOM
	nodeLists, err := h.impl.GetNodeGraphs(opts, bom)
	if err != nil {
		return nil, fmt.Errorf("extracting the node dependencies")
	}

	// Parse any other documents providing vex data for any components
	vexDocs, err := h.impl.ParseExtraDocuments(opts)
	if err != nil {
		return nil, fmt.Errorf("parsing extra documents: %w", err)
	}

	// Discover the component vex data
	discoveryDocs, err := h.impl.DiscoverComponentVexData(opts, bom.NodeList)
	if err != nil {
		return nil, fmt.Errorf("dicovering component VEX data: %w", err)
	}
	vexDocs = append(vexDocs, discoveryDocs...)

	// In the end, the extraDocsDoc will be the combined result of merging
	// the autodiscovered documents plus any supplementals supplied to the handler
	extraDocsDoc, err := h.impl.MergeExtraDocs(opts, vexDocs)
	if err != nil {
		return nil, err
	}

	statements := []*vex.Statement{}

	// Now, lets generate the vex data for each software piece
	for i, nl := range nodeLists {
		nodeStatements, err := h.impl.GenerateVexData(opts, nl, extraDocsDoc)
		if err != nil {
			return nil, fmt.Errorf("generating VEX data for node #%d", i)
		}
		statements = append(statements, nodeStatements...)
	}

	doc, err := h.impl.AssembleDocument(opts, statements)
	if err != nil {
		return nil, fmt.Errorf("assembling document: %w", err)
	}

	return doc, err
}

// VexSBOMFile generates VEX data from a file
func (h *Handler) VexSBOMFile(opts *Options, filePath string) (*vex.VEX, error) {
	file, err := h.impl.OpenFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	defer file.Close()

	return h.VexSBOM(opts, file)
}

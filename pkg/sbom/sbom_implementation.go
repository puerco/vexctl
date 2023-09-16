package sbom

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/bom-squad/protobom/pkg/reader"
	protobom "github.com/bom-squad/protobom/pkg/sbom"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/sirupsen/logrus"
)

// sbomHandlerImplementation defines the functions that implement the functionality
// of the SBOM handler. This interface is also used to generate the fakes used for
// integration tests.
type sbomHandlerImplementation interface {
	ParseSBOM(io.ReadSeeker) (*protobom.Document, error)
	GetNodeGraphs(*Options, *protobom.Document) ([]*protobom.NodeList, error)
	ParseExtraDocuments(*Options) ([]*vex.VEX, error)
	MergeExtraDocs(*Options, []*vex.VEX) (*vex.VEX, error)
	GenerateVexData(*Options, *protobom.NodeList, *vex.VEX) ([]*vex.Statement, error)
	AssembleDocument(*Options, []*vex.Statement) (*vex.VEX, error)
	OpenFile(string) (*os.File, error)
}

type defaultHandlerImplementation struct{}

// ParseSBOM gets a stream and reads an SBOM from it
func (dhi *defaultHandlerImplementation) ParseSBOM(r io.ReadSeeker) (*protobom.Document, error) {
	reader := reader.New()
	return reader.ParseStream(r)
}

// GetNodeGraphs returns the graph fragments of the specified nodes
func (dhi *defaultHandlerImplementation) GetNodeGraphs(opts *Options, bom *protobom.Document) ([]*protobom.NodeList, error) {
	nodes := opts.Nodes
	if len(opts.Nodes) == 0 {
		nodes = bom.NodeList.RootElements
	}

	ret := []*protobom.NodeList{}
	for _, nodeID := range nodes {
		// nl := bom.NodeList.NodeSiblings(nodeID)
		nl := bom.NodeList.NodeGraph(nodeID)
		if len(nl.RootElements) == 0 {
			return nil, fmt.Errorf("unable to get dependency graph of %s", nodeID)
		}
		ret = append(ret, nl)
	}

	return ret, nil
}

// ParseExtraDocuments takes vex paths from options and parses them
func (dhi *defaultHandlerImplementation) ParseExtraDocuments(opts *Options) ([]*vex.VEX, error) {
	ret := []*vex.VEX{}
	for _, path := range opts.VexFiles {
		doc, err := vex.Open(path)
		if err != nil {
			return nil, fmt.Errorf("parsing VEX document at %s: %w", path, err)
		}
		ret = append(ret, doc)
	}
	return ret, nil
}

// MergeExtraDocs combines all the extra documents into one for simpler handling
func (dhi *defaultHandlerImplementation) MergeExtraDocs(opts *Options, docs []*vex.VEX) (*vex.VEX, error) {
	// It there are no supplemental documents, we return an empty document.
	if len(docs) == 0 {
		return &vex.VEX{}, nil
	}
	doc, err := vex.MergeDocuments(docs)
	if err != nil {
		return nil, fmt.Errorf("merging documents: %w", err)
	}

	return doc, nil
}

// AssembleDocument returns a new document with the VEX statements that apply to
// the SBOM components
func (dhi *defaultHandlerImplementation) AssembleDocument(opts *Options, statements []*vex.Statement) (*vex.VEX, error) {
	doc := vex.New()
	for _, s := range statements {
		doc.Statements = append(doc.Statements, *s)
	}

	return &doc, nil
}

type productStatementIndex map[*protobom.Node][]*vex.Statement

// findNodeStatements takes a document and a list of SBOM nodes and returns
// the statements that match
func findNodeStatements(doc *vex.VEX, nodes []*protobom.Node) productStatementIndex {
	ret := productStatementIndex{}

	for _, n := range nodes {
		for i := range doc.Statements {
			if statementMatchesNode(doc.Statements[i], n) {
				if _, ok := ret[n]; !ok {
					ret[n] = []*vex.Statement{}
				}
				ret[n] = append(ret[n], &doc.Statements[i])
			}
		}
	}

	return ret
}

// statementMatchesProduct returns true if a statement matches a product
// by looking for matches by Id and software identifiers
func statementMatchesNode(s vex.Statement, n *protobom.Node) bool {
	// First, key on the ID
	logrus.Infof("Testing match for %s: %s", s.Vulnerability.Name, n.Id)
	if s.Matches(string(s.Vulnerability.Name), n.Id, nil) {
		return true
	}

	// If no luck, check the identifiers
	for _, identifier := range n.Identifiers {
		logrus.Infof("Testing match for %s: %s", s.Vulnerability.Name, identifier)
		if s.Matches(string(s.Vulnerability.Name), identifier, nil) {
			logrus.Warn("MATCH!")
			return true
		}
	}
	return false
}

// GenerateVexData generates the VEX data for a given SBOM component.
func (dhi *defaultHandlerImplementation) GenerateVexData(opts *Options, nl *protobom.NodeList, extraDocsDoc *vex.VEX) ([]*vex.Statement, error) {
	statements := []*vex.Statement{}
	if len(nl.RootElements) == 0 {
		return nil, errors.New("nodelist does not have a top level component")
	}

	// Index the document statements by product
	statementIndex := findNodeStatements(extraDocsDoc, nl.Nodes)
	// Get the root node and...
	rootNode := nl.GetNodeByID(nl.RootElements[0])
	// ... generate a VEX product from it. It will be used as the
	// product for all transitioned statements
	product := nodeToProduct(rootNode)

	for node, nodeStatements := range statementIndex {
		// Statements that talk about our product are previous VEX
		// data about it, so we just add them as they are
		if node.Id == rootNode.Id {
			statements = append(statements, nodeStatements...)
			continue
		}

		// All others are statements about the components. And we need to
		// transition them, first convert the node to product
		for _, componentStatement := range nodeStatements {
			transitionedStatement, err := transitionStatement(componentStatement, []vex.Product{*product})
			if err != nil {
				return nil, fmt.Errorf("transitioning statement: %w", err)
			}
			statements = append(statements, transitionedStatement)
		}
	}

	return statements, nil
}

func nodeToProduct(n *protobom.Node) *vex.Product {
	p := &vex.Product{
		Component: vex.Component{
			Hashes:      map[vex.Algorithm]vex.Hash{},
			Identifiers: map[vex.IdentifierType]string{},
		},
		Subcomponents: []vex.Subcomponent{},
	}

	for t, i := range n.Identifiers {
		var vexIdentifierType vex.IdentifierType
		switch t {
		case int32(protobom.SoftwareIdentifierType_PURL):
			vexIdentifierType = vex.PURL
			p.ID = string(i) // The identifier
		}
		p.Identifiers[vexIdentifierType] = string(i)
	}

	for algo, hashVal := range n.Hashes {
		p.Hashes[vex.Algorithm(algo)] = vex.Hash(hashVal)
	}
	return p
}

// Transition takes a statement with an empty product set and transitions
// it to become the VEX statement of the new products.
//
// Transitioning is the process of generating a VEX statement of product by
// incorporating VEX data from its components. The product of the original statement
// (the component) _transitions_ to the subcomponents sections giving way to the
// new product.
//
// This function returns a new statement, so the original ID is lost in the process.
// The original
//
// The new products must have no subcomponents or transition will throw an error.
func transitionStatement(s *vex.Statement, products []vex.Product) (*vex.Statement, error) {
	// Create a new set of subcomponents
	subComps := []vex.Subcomponent{}
	for _, p := range s.Products {
		subComps = append(subComps, vex.Subcomponent{
			Component: p.Component,
		})
	}

	// Check that the new products don't have any subcomponents and add the
	// transitioned products to the subcomponent section
	for i := range products {
		if len(products[i].Subcomponents) > 0 {
			return nil, fmt.Errorf(
				"unable to transition statement, product #%d has subcomponents set", i,
			)
		}
		products[i].Subcomponents = subComps
	}

	return &vex.Statement{
		Vulnerability:            s.Vulnerability,
		Timestamp:                s.Timestamp,
		LastUpdated:              s.LastUpdated,
		Products:                 products,
		Status:                   s.Status,
		StatusNotes:              s.StatusNotes,
		Justification:            s.Justification,
		ImpactStatement:          s.ImpactStatement,
		ActionStatement:          s.ActionStatement,
		ActionStatementTimestamp: s.ActionStatementTimestamp,
	}, nil
}

// OpenFile opens a file and returns a pointer to it
func (dhi *defaultHandlerImplementation) OpenFile(filePath string) (*os.File, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening SBOM file: %w", err)
	}
	return f, nil

}

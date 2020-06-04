package pelican

import (
	"github.com/SilentTTxo/pelican/pe"

	"github.com/itchio/headway/state"
	"github.com/itchio/httpkit/eos"
	"github.com/pkg/errors"
)

type ProbeParams struct {
	Consumer *state.Consumer
	// Return errors instead of printing warnings when
	// we can't parse some parts of the file
	Strict bool
}

// https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#resource-directory-table  Resource Table
const ResourceTableIdx = 2

// Probe retrieves information about an PE file
func Probe(file eos.File, params ProbeParams) (*PeInfo, error) {
	consumer := params.Consumer

	pf, err := pe.NewFile(file)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	info := &PeInfo{
		VersionProperties: make(map[string]string),
	}

	switch pf.Machine {
	case pe.IMAGE_FILE_MACHINE_I386:
		info.Arch = "386"
	case pe.IMAGE_FILE_MACHINE_AMD64:
		info.Arch = "amd64"
	}

	imports, err := pf.ImportedLibraries()
	if err != nil {
		if params.Strict {
			return nil, errors.WithMessage(err, "while parsing imported libraries")
		}
		consumer.Warnf("Could not parse imported libraries: %+v", err)
	}
	info.Imports = imports

	sect := pf.Section(".rsrc")
	if sect != nil {
		err = params.parseResources(info, sect)
		if err != nil {
			if params.Strict {
				return nil, errors.WithMessage(err, "while parsing resources")
			}
			consumer.Warnf("Could not parse resources: %+v", err)
		}
	} else {
		var dd [16]pe.DataDirectory
		switch oh := pf.OptionalHeader.(type) {
		case *pe.OptionalHeader32:
			dd = oh.DataDirectory
		case *pe.OptionalHeader64:
			dd = oh.DataDirectory
		}

		ResourceTable := dd[ResourceTableIdx]

		sect := pf.GetSectionByRva(ResourceTable.VirtualAddress)

		err = params.parseResources(info, sect)
	}

	return info, nil
}

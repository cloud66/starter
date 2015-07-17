package packs

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/cloud66/starter/common"
)

type DockerfileContextBase struct {
	Version  string
	Packages *common.Lister
}

type DockerfileWriterBase struct {
	PackElement
	TemplateDir     string
	OutputDir       string
	ShouldOverwrite bool
}

func (w *DockerfileWriterBase) Write(context interface{}) error {
	templateName := fmt.Sprintf("%s.dockerfile.template", w.GetPack().Name())
	destName := "Dockerfile"

	tmpl, err := template.ParseFiles(filepath.Join(w.TemplateDir, templateName))
	if err != nil {
		return err
	}

	destFullPath := filepath.Join(w.OutputDir, destName)

	if _, err := os.Stat(destFullPath); !os.IsNotExist(err) && !w.ShouldOverwrite {
		return fmt.Errorf("File %s exists and will not be overwritten unless the overwrite flag (-o) is set\n", destName)
	}

	fmt.Printf("%s Writing %s...%s\n", common.MsgL1, destName, common.MsgReset)
	destFile, err := os.Create(destFullPath)
	if err != nil {
		return err
	}
	defer func() {
		if err := destFile.Close(); err != nil {
			fmt.Printf("%s Cannot close file %s due to %s\n", common.MsgError, destName, err.Error())
		}
	}()
	err = tmpl.Execute(destFile, context)
	if err != nil {
		return err
	}

	return nil
}
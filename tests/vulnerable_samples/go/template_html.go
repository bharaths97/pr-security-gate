package main

import "html/template"

func render(body string) template.HTML {
	return template.HTML(body)
}

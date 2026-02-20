from weasyprint import HTML
HTML('<h1>Test</h1>').write_pdf('/tmp/test.pdf')
print("✅ PDF généré avec succès !")

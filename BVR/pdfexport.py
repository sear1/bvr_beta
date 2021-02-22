#requres https://wkhtmltopdf.org/downloads.html
import pdfkit

options = {
    'page-size': 'Executive',
    'encoding': "UTF-8",
    'custom-header' : [
        ('Accept-Encoding', 'gzip')
    ],
    'cookie': [
        ('cookie-name1', 'cookie-value1'),
        ('cookie-name2', 'cookie-value2'),
    ],
    'no-outline': None
}

pdfkit.from_url('http://127.0.0.1:5000/account_id','bvrexample.pdf', options=options) 

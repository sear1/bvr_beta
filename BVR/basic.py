from flask import Flask, render_template, redirect, url_for
import datetime
import pandas as pd

###SQL query###
#set account info as a login and force SQL query to filter on account_id
###


app = Flask(__name__)


@app.route('/<account_id>',methods=['GET', 'POST'])
def bvr_account(account_id):
    """
    Default page account call.
    """
    bvr_account_id= "1111"
    
    bvr_oat_score = 12
    bvr_vulnerability_score = 2
    bvr_total_score = int(bvr_oat_score) + int(bvr_vulnerability_score)

    #website=example_website = ["example.com", "api.sample.com"]

    if account_id in bvr_account_id:
        bvr_account_id= "1111"
    else:
        pass

    
    overview_vulnerability_table = ("Website", "Total Proxied Traffic", "Total Vulnerabilites Events", "Total Mitigated Vulnerabilies", "Top OWASP Automated Threat", "Top Technique")
    overview_vulnerability_data = (
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
        ("example.com", "99999", "88888", "88887:99%", "OAT-12", "Scraping"),
    )

    heading_tb = ("Date",  "OAT", "IP Address", "User-Agent", "ISP", "Country", "Events")
    data_tb = (
        ("01/01/2021", "OAT-1","128.0.0.1", "PhantomJS", "Amazon.com", "US", "999"),
        ("01/02/2021", "OAT-1","128.0.0.1", "NightareJS", "Amazon.com", "US", "999"),
        ("01/03/2021", "OAT-1","128.0.0.1", "Puppeteer", "Amazon.com", "US", "999"),
    )

    remedy_tb = ("Date",  "Vulnerability", "Stock Condition", "Events")
    remedy_db = (
        ("01/01/2021", "Bad PID", "(all (pid == 'example')", "99"),
        ("01/02/2021", "Bad User-Agent", "(all (headers.user_agent == 'bad bot')", "88"),
        ("01/03/2021", "Bad Request", "(all (not header.accept_lang?))", "11"),
    )

    return render_template('final_draft.html', 
                            account_id=account_id,
                            bvr_account_id=bvr_account_id,
                            ov_tb=overview_vulnerability_table,
                            ov_db=overview_vulnerability_data,
                            rem_tb=remedy_tb,
                            rem_db=remedy_db,
                            total_score=bvr_total_score, 
                            oat_score=bvr_oat_score, 
                            v_score=bvr_vulnerability_score,
                            table1h=heading_tb,
                            table1d=data_tb)

@app.route('/BVR/<global_trends_id>',methods=['GET', 'POST'])
def bvr_global(global_trends_id):
    """
    Global bot trends call.
    """
    global_trends = "Global"
    return render_template('bvr_global.html', global_trends_id=global_trends)

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

if __name__ == '__main__':
    app.run(debug=True)
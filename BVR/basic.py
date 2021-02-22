from flask import Flask, render_template, redirect, url_for, request 
import datetime
from pyhive import presto
import requests
from requests.auth import HTTPBasicAuth
import pandas as pd

start = '2021-02-01'
end = '2021-02-03'
abp_account_id = ''
ldap_user_name = 'user.name'
ldap_password = 'password'

##SQL connect
req_kw = {
    'auth': HTTPBasicAuth(f'{ldap_user_name}', f'{ldap_password}'),
    'verify': '/Library/simba/prestoodbc/lib/cacerts.pem',
}

conn = presto.connect(
    host='bon-presto.dstl-infra.net',
    port=443,
    protocol='https',
    catalog='hive',
    schema='bon_log_prod',
    requests_kwargs=req_kw,
)
cursor  = conn.cursor()


#
app = Flask(__name__)

v1 = ('Vulernability 1', 'High', '#')
v2 = ('Vulernability 1', 'High', '#')

#define login in for LDAP and Region
#index page has you sumbit LDAP and select region from drop down


@app.route('/<account_id>',methods=['GET', 'POST'])
def bvr_account(account_id):
    """
    Default page account call.
    """

    query1 = f"""
        select access_time, ip, headers_user_agent, geo_org, count(*)
        from bon_log_prod.access
        where ds >= '{start}' and ds <= '{end}'
        and headers_accept_encoding is null
        and not (request_path like ('%.js%')
            or request_path like ('%.png%'))
        and not category = 'good_bot'
        and not (contains(flags,'search_engine')
            or contains(flags,'known_violator'))
        and not ua_category = 'crawler'
        and not request_path like ('%/v6/challenge/%')
        and action is null
        group by 1,2,3,4
        limit 5
        """
    col = ['Date', 'IP', 'User Agent', 'ISP Provider', 'Events']   

    #UNION all
    
    cursor.execute(query1)
    #my_results = cursor.fetchall()
    #return my_results
    df = pd.DataFrame(cursor.fetchall(), columns=col)
    #return df
    #test_table = df.columns.value
    #test_data= df.to_html(classes='data')
    ## garbage

    bvr_account_id= "1111"
    
    bvr_oat_score = 12
    bvr_vulnerability_score = 2
    bvr_total_score = int(bvr_oat_score) + int(bvr_vulnerability_score)


    if account_id in bvr_account_id:
        bvr_account_id= "1111"
    else:
        pass
    
    overview_vulnerability_table = ("Website", "Total Vulnerabilites Events", "Low Threats", "Medium Threats", "Critical Threats")
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

    heading_tb = ("Date", "IP Address", "User-Agent", "ISP", "Country", "Events")
    data_tb = (
        ("01/01/2021","128.0.0.1", "PhantomJS", "Amazon.com", "US", "999"),
        ("01/02/2021","128.0.0.1", "NightareJS", "Amazon.com", "US", "999"),
        ("01/03/2021","128.0.0.1", "Puppeteer", "Amazon.com", "US", "999"),
    )

    remedy_tb = ("Date",  "Vulnerability", "Stock Condition", "Events")
    remedy_db = (
        ("01/01/2021", "Bad PID", "(all (pid == 'example')", "99"),
        ("01/02/2021", "Bad User-Agent", "(all (headers.user_agent == 'bad bot')", "88"),
        ("01/03/2021", "Bad Request", "(all (not header.accept_lang?))", "11"),
    )
    ###

    today_utc = datetime.date.today()
    monthly_utc = datetime.date.today() - datetime.timedelta(30)

    return render_template('final_draft.html', 
                            account_id=account_id,
                            column_names=df.columns.values,
                            row_data=list(df.values.tolist()),
                            zip=zip,
                            bvr_account_id=bvr_account_id,
                            ov_tb=overview_vulnerability_table,
                            ov_db=overview_vulnerability_data,
                            rem_tb=remedy_tb,
                            rem_db=remedy_db,
                            today=today_utc, 
                            past_month=monthly_utc, 
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
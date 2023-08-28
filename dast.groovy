/* groovylint-disable DuplicateStringLiteral, UnnecessaryToString */

import jenkins.model.Jenkins
import com.cloudbees.plugins.credentials.CredentialsProvider
import groovy.json.JsonSlurper
import java.text.SimpleDateFormat
import net.sf.json.JSON
import net.sf.json.JSONObject
import com.cloudbees.groovy.cps.NonCPS
import groovy.json.*


void call(setupVar) {
    def appId
    def appName
    def appVersion
    def settingId
    def steps

    def config = this.loadConfig(setupVar)
    def applicationId

    // echo config

        
        appName = config.app_name
        appVersion = config.app_version
        this.loginSessionSSC(config.BASE_SSC_URL)
        def detailApps = this.getDetailAppVersion(appName, appVersion)
        appId = detailApps.id
        applicationId = detailApps.application.id
    


        def scanType = config.dast.scan_type
        if (scanType == 'STANDARD') {
            settingId = this.getSettingId(appId, config)
        } else if (scanType == 'API') {
            settingId = config.dast.cicd_token_api
        }

        def scanName = config.app_name
        def storeParm = 'v' + appId
        this.loginSessionDAST(config.BASE_SSC_URL)
        //this.startScan(scanName, settingId, config.dast.url , storeParm)
        //this.waitScan(storeParm, config.SCAN_CHECK_DELAY, config.WAITING_SCAN_TIME)
        //this.importToSSC(storeParm)

        echo "Enable Quality Gate ? ${config.enable_dast_gate}"
        if (config.enable_dast_gate) {
            this.evaluateVulnerabilityDAST(appId, config)
        }
   


        def reports = ['Application_Report', 'Vulnerability_Report' ] as String[]
        def appReport
        for (report in reports) {
            appReport = this.generateReport(report, appId, applicationId, config)

            reportLocation = this.processReport(appReport.id, appReport.name, config)
        }
    
    
}

def loadConfig(setupVar){
    def BASE_DAST_API_URL = "http://10.253.21.13:8081/api"
    def BASE_SSC_API_URL = "http://10.253.21.16:8080/ssc/api/v1"
    def WAITING_SCAN_TIME = "24h"
    def SCAN_CHECK_DELAY = "300s"
    def SSC_SENSOR_VER = "22.1.0.321"
    def REPORT_DIR = "/var/lib/jenkins/report" 
    def BASE_SSC_URL = "http://10.253.21.16:8080/ssc/"
    def config = [
        "app_name" : setupVar.environment['appName'],
        "app_version"  : setupVar.environment['app_version'],
        "BASE_SSC_URL" : BASE_SSC_URL,
        "BASE_SSC_API_URL" : BASE_SSC_API_URL,
        "BASE_DAST_API_URL" : BASE_DAST_API_URL,
        "WAITING_SCAN_TIME" : WAITING_SCAN_TIME,
        "SCAN_CHECK_DELAY" : SCAN_CHECK_DELAY,
        "SSC_SENSOR_VER" : SSC_SENSOR_VER,
        "REPORT_DIR" : REPORT_DIR,
        "dast" : [
            "scan_type" : setupVar.environment['dast']['scan_type'],
            "url" : setupVar.environment['dast']['url'],
            "webmacro" : setupVar.environment['dast']['webmacro'],
            "cicd_token_api" : setupVar.environment['dast']['cicd_token_api'],
        ],
        //"enable_dast_gate" : setupVar.environment['enable_dast_gate'].toBoolean(),
        "enable_dast_gate" : true,
        "dast_gate" : [
            "critical" : setupVar.environment['dast_gate']['critical'],
            "high" : setupVar.environment['dast_gate']['high'],
            "medium" : setupVar.environment['dast_gate']['medium'],
            "low" : setupVar.environment['dast_gate']['low']
        ]
    ]
    // echo config
    return config
} 

// Fortify Helper

def runsh(steps, String cmd, Boolean isPrint) {
    def result = steps.sh(
        script: cmd,
        returnStdout: true
    ).trim()
    if (isPrint) {
        steps.echo result.toString()
    }
    return result.toString()
}

def runsh(steps, String cmd) {
    steps.sh cmd
}

def jsonToObject(jsonStr) {
    def jsonSlurper = new JsonSlurper()
    def result = jsonSlurper.parseText(jsonStr)
    return result
}

def getCredentials(credentialsId) {
    // Get the Jenkins instance
    def jenkins = Jenkins.getInstance()

    // Retrieve the credentials by ID
    def credentials = CredentialsProvider.lookupCredentials(
        com.cloudbees.plugins.credentials.common.StandardCredentials,
        jenkins,
        null,
        null
    ).find {
        it.id == credentialsId
    }

    return credentials.getSecret()
}

def currentDateTime(String format='yyyy-MM-dd HH:mm:ss') {
    def date = new Date()
    def sdf = new SimpleDateFormat(format)
    return sdf.format(date)
}  

// Configure SSC
    
Boolean isActiveSessionSSC() {
    steps.echo 'Check is Any SSC Session Active'
    def cmd = 'fcli ssc session list --output=json'
    def result = this.runsh(steps, cmd, false)
    def session =  this.jsonToObject(result)
    int totalActiveSession = session.size()

    def isActive = true
    if (totalActiveSession == 0) {
        isActive = false
    }
    return isActive
}

def loginSessionSSC(BASE_SSC_URL) {
    if (!this.isActiveSessionSSC()) {
        steps.echo 'No Active SSC Session Detected \nCreate New Session'
        String cmd = "fcli ssc session login --url ${BASE_SSC_URL} --ci-token " + this.getCredentials('SSC_CI_TOKEN')
        this.runsh(steps, cmd)
    }
}

def getDetailAppVersion(appName, appVersion) {
    steps.echo 'Get Detail Application ' + appName + ':' + appVersion
    String cmdCreateIfNotExist = "fcli ssc appversion create ${appName}:${appVersion} --auto-required-attrs  --skip-if-exists"
    this.runsh(steps, cmdCreateIfNotExist)
    String cmdGetDetailApps = "fcli ssc appversion get ${appName}:${appVersion} -o=json"
    def strdetailApps = this.runsh(steps, cmdGetDetailApps, true)
    def detailApps = this.jsonToObject(strdetailApps)
    return detailApps
}

def evaluateVulnerabilitySAST(appId, configJson) {
    boolean result = false
    def config = configJson
    def cmd = "fcli ssc appversion-vuln count --appversion ${appId} -o=json"
    def str_vuln = this.runsh(steps, cmd, true)
    def list_vuln = this.jsonToObject(str_vuln)
    int critical = 0
    int high = 0
    int medium = 0
    int low = 0

    for (vuln in list_vuln) {
        switch (vuln.id) {
            case 'Critical':
                critical = vuln.totalCount
                break
            case 'High' :
                high = vuln.totalCount
                break
            case 'Medium' :
                medium = vuln.totalCount
                break
            case 'Low' :
                low = vuln.totalCount
                break
        }
    }

    steps.echo "Critial : ${critical} | Allowed : ${config.sast_gate.critical} "
    steps.echo "High : ${high} | Allowed : ${config.sast_gate.high} "
    steps.echo "Medium : ${medium} | Allowed : ${config.sast_gate.medium} "
    steps.echo "Low : ${low} | Allowed : ${config.sast_gate.low} "

    if (critical > config.sast_gate.critical || high > config.sast_gate.high || medium > config.sast_gate.medium || low > config.sast_gate.low) {
        steps.error 'Not Pashed\nScan Result not achieve minimum allowed vulnerability'
        steps.currentBuild.result = 'FAILURE'
    } else {
        steps.echo 'Quality Gate - Pashed'
    }

    return result
}

def evaluateVulnerabilityDAST(appId, configJson) {
    boolean result = false
    def config = configJson
    def cmd = "fcli ssc appversion-vuln count --appversion ${appId} -o=json"
    def str_vuln = this.runsh(steps, cmd, true)
    def list_vuln = this.jsonToObject(str_vuln)
    int critical = 0
    int high = 0
    int medium = 0
    int low = 0

    for (vuln in list_vuln) {
        switch (vuln.id) {
            case 'Critical':
                critical = vuln.totalCount
                break
            case 'High' :
                high = vuln.totalCount
                break
            case 'Medium' :
                medium = vuln.totalCount
                break
            case 'Low' :
                low = vuln.totalCount
                break
        }
    }

    steps.echo "Critial : ${critical} | Allowed : ${config.dast_gate.critical} "
    steps.echo "High : ${high} | Allowed : ${config.dast_gate.high} "
    steps.echo "Medium : ${medium} | Allowed : ${config.dast_gate.medium} "
    steps.echo "Low : ${low} | Allowed : ${config.dast_gate.low} "

    if (critical > config.dast_gate.critical || high > config.dast_gate.high || medium > config.dast_gate.medium || low > config.dast_gate.low) {
        steps.error 'Not Pashed\nScan Result not achieve minimum allowed vulnerability'
        steps.currentBuild.result = 'FAILURE'
    } else {
        steps.echo 'Quality Gate - Pashed'
    }

    return result
}

// DAST Configurationn


Boolean isActiveSessionDAST() {
    steps.echo 'Check is Any DAST Session Active'
    def cmd = 'fcli sc-dast session list --output=json'
    def result = this.runsh(steps, cmd, true)

    def session =  this.jsonToObject(result)
    int totalActiveSession = session.size()

    def isActive = true
    if (totalActiveSession == 0) {
        isActive = false
    }
    return isActive
}

def loginSessionDAST(BASE_SSC_URL) {
    if (!this.isActiveSessionDAST()) {
        steps.echo 'No Active DAST Session Detected \nCreate New Session'
        String cmd = 'fcli sc-dast session login --ssc-url ' + BASE_SSC_URL + ' --ssc-ci-token ' + this.getCredentials('SSC_CI_TOKEN')
        this.runsh(steps, cmd)
    }
}

def startScan(scanName, settingId, url, storeParm) {
    // fcli sc-dast scan start ${env.SCAN_NAME} --settings ${env.CICD_TOKEN} --start-url ${env.APP_URL} --store scanId
    def cmd = "fcli sc-dast scan start ${scanName} --settings ${settingId} --start-url ${url} --store ${storeParm}"
    this.runsh(steps, cmd)
    return storeParm
}

def waitScan(scanId, SCAN_CHECK_DELAY, WAITING_SCAN_TIME) {
    def cmd = "fcli sc-dast scan wait-for {?${scanId}:id} -i " + SCAN_CHECK_DELAY + ' -t ' + WAITING_SCAN_TIME
    this.runsh(steps, cmd)
}

def importToSSC(scanId) {
    def cmd = "fcli sc-dast scan retry import-results {?${scanId}:id} --log-level DEBUG"
    this.runsh(steps, cmd)
}

def getLastSettingId(appId,config) {
    def settingId = null
    def authorization = this.getCredentials('SSC_CI_TOKEN_API')
    
    def cmd = """
        curl -s \
        --location "${config.BASE_DAST_API_URL}/application-versions/${appId}/scan-settings" \
        --header "Authorization: FortifyToken ${authorization}" \
        --header 'Content-Type: application/json' \
    """
    def strBinnaryFileData = this.runsh(steps,cmd,true)
    def binnaryFileData = this.jsonToObject(strBinnaryFileData)

    int totalItems = binnaryFileData.totalItems
    if (totalItems > 0) {
        def last_setting = binnaryFileData.items[totalItems - 1]
        settingId = last_setting.cicdToken
    }
    
    echo "SettingId : ${settingId}"
    return settingId
}

def getUploadSession(appId, filePath,fileType,config) {
    def auth = this.getCredentials('SSC_CI_TOKEN_API')
    
    def cmdExtention = 'filename="' + filePath + '"; extension="\${filename##*.}"; echo "\$extension" '
    def fileExtention = '.' + this.runsh(steps, cmdExtention, false)
    filename = this.runsh(steps, "basename ${filePath} ${fileExtention}", false)
    def filesize = this.runsh(steps,'stat --printf="%s" '+filePath,false)

    def cmd = """
        curl -s \
        --location "${config.BASE_DAST_API_URL}/application-version-binary-files/upload-session" \
        --header "Authorization:  FortifyToken ${auth}" \
        --header 'Content-Type: application/json' \
        --header 'Accept: application/json' \
        --data "{
            'applicationVersionId': ${appId},
            'fileName': '${filename}',
            'fileExtension': '${fileExtention}',
            'fileType': ${fileType},
            'fileLength': ${filesize}
        }"
    """
    def strBinnaryFileData = this.runsh(steps,cmd,true)
    def binnaryFileData = this.jsonToObject(strBinnaryFileData)

    return binnaryFileData.id
        
}

def uploadBinnaryFile(appId, filePath,fileType, config){
    def sessionId = this.getUploadSession(appId,filePath,fileType,config)
    def rawFile = this.runsh(steps,"cat "+filePath,false)
    def auth = this.getCredentials('SSC_CI_TOKEN_API')
    def cmd = """
        curl -s \
        --location "${config.BASE_DAST_API_URL}/application-version-binary-files/upload?applicationVersionId=${appId}&sessionId=${sessionId}&offset=0" \
        --header "Authorization:  FortifyToken ${auth}" \
        --header 'Content-Type: text/plain' \
        --data '${rawFile.replaceAll("\\s", "")}'
    """
    def strBinnaryFileData = this.runsh(steps,cmd,true)
    def binnaryFileData = this.jsonToObject(strBinnaryFileData)

    return [
        "id" : binnaryFileData.id,
        "hosts" : binnaryFileData.hosts
    ]
}

def generateSettingStandard(appId, webmacroData, url, config){
    def loginMacroBinaryFileId = 'null'
    def hasSiteAuthentication = false
    def allowedHosts
    if(webmacroData) {
        loginMacroBinaryFileId = webmacroData.id
        hasSiteAuthentication = true
        for (host in webmacroData.hosts) {
            allowedHosts = "{ 'hostName' : '" + host + "'},"
        }
    } else {
        allowedHosts = "{ 'hostName' : '" + config.dast.url + "'}"
    }
    def settingname = config.app_name+'_'+config.app_version
    def auth = this.getCredentials('SSC_CI_TOKEN_API')

    def cmd = """
        curl -s --location "${config.BASE_DAST_API_URL}/application-version-scan-settings" \
        --header "Authorization: FortifyToken ${auth}" \
        --header 'Content-Type: application/json' \
        --data "{
            'applicationVersionId': ${appId},
            'scanType': 1,
            'submitForAudit': false,
            'scanSettings': {
                'scanMode': 2,
                'startUrls': ['${url}'],
                'allowedHosts': [${allowedHosts.toString()}],
                'workflowDrivenMacroBinaryFileIds': [],
                'userAgentType': 1,
                'restrictToFolder': false,
                'hasSiteAuthentication': ${hasSiteAuthentication.toString()},
                'hasNetworkAuthentication': false,
                'networkAuthenticationSettings': {
                    'networkAuthenticationType': 5
                },
                'manualProxySettings': null,
                'useProxyServer': true,
                'proxySettingsType': 5,
                'spaOptionType': 1,
                'scanPriority': 1,
                'useScannerScaling': false,
                'dataRetentionDays': 180,
                'redundantPageDetectionSettings': {
                    'pageSimilarityThreshold': 95,
                    'tagAttributesToInclude': ['id', 'class'],
                    'isEnabled': false
                },
                'clientCertificateSettings': {
                    'isEnabled': false,
                    'requiresPassword': false,
                    'clientCertificateBinaryFileId': null
                },
                'truClientMacroParameters': [],
                'restrictedScanSettings': [],
                'apiDefinitionBinaryFileId': null,
                'exclusions': [],
                'policyId': '8d40b5de-8775-4a93-ad2a-139f17375247',
                'customUserAgent': null,
                'proxyPACUrl': '',
                'loginMacroBinaryFileId': ${loginMacroBinaryFileId.toString()},
                'enableTrafficMonitor': false,
                'enableSASTCorrelation': false
            },
            'name': '${settingname}',
            'sourceScanSettingsId': null,
            'sourceScanSettingsType': null
        }"

    """
    def strSetting = this.runsh(steps, cmd, true)
    def setting = this.jsonToObject(strSetting)
    return setting.cicdToken
}

def validAPI(appId, collection, env, auth=null, config){
    def url = config.BASE_DAST_API_URL+"/application-versions/"+appId+"/build-postman-auth-settings"
    def authorization = "FortifyToken "+this.getCredentials('SSC_CI_TOKEN_API')
    def request= """
        curl '${url}' \
        -H 'Authorization: ${authorization}' \
        -H 'Content-Type: application/json' \
        --data '{
            "postmanCollectionBinaryFileIds":[${collection.toString()}],
            "postmanAuthCollectionBinaryFileId":${auth.toString()},
            "postmanEnvCollectionBinaryFileId":${env.toString()},
            "useProxyServer":true,
            "proxySettingsType":5,
            "manualProxySettings":{}
        }'
    """

    this.runsh(steps, cmd, null )
}

def getSettingId(appId, config) {
    
    def settingId = this.getLastSettingId(appId, config)
    def scanType = config.dast.scan_type
    def fileType
    steps.echo scanType
    if (! settingId) {
        if (scanType == 'STANDARD') {
            def webmacroData
            if (config.dast.webmacro) {
                fileType = "2"
                webmacroData = uploadBinnaryFile(appId, config.dast.webmacro, fileType, config)
            }
            settingId = generateSettingStandard(appId, webmacroData, config.dast.url,config)
        } else if (scanType == 'API') {
           echo "Scan API need CICD Token"

        }
    }

    return settingId
}  

// Configuration Report

def getDetailReport(id,config) {

    def auth = 'FortifyToken ' + this.getCredentials('SSC_CI_TOKEN_API')
    def url = config.BASE_SSC_API_URL+'/reports/'+id.toString()
    def cmd = """
        curl -s \
        --location "${url}" \
        --header "Authorization: ${auth}"
    """
    def strDetailReport = this.runsh(steps,cmd,true)
    def detailReport = this.jsonToObject(strDetailReport)
    return detailReport.data

}

String getReportStatus(id, config){
    def report = this.getDetailReport(id, config)
    return report.status
}

def generateReport(reportType, appId, applicationId,config){
    def requestURL = config.BASE_SSC_API_URL+ '/reports'
    def authorization = 'FortifyToken ' + this.getCredentials('SSC_REPORT_TOKEN')
    def inputReportParam
    def type
    def reportDefinitionId
    switch(reportType) {
    case 'Application_Report':
        type = "PROJECT"
        reportDefinitionId = "1"
        inputReportParam = """
                    {
                        "name": "Include OWASP Top Ten 2021",
                        "identifier": "includeOWASP2021",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include PCI DSS 3.2.1",
                        "identifier": "includePCI321",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include PCI SSF 1.0",
                        "identifier": "includePCISSF10",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include CWE",
                        "identifier": "includeCWE",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include WASC 2.00",
                        "identifier": "includeWASC2",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include DISA STIG 5.1",
                        "identifier": "includeSTIG51",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix A",
                        "identifier": "includeAppendixA",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix B",
                        "identifier": "includeAppendixB",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix C",
                        "identifier": "includeAppendixC",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix D",
                        "identifier": "includeAppendixD",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix E",
                        "identifier": "includeAppendixE",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
                    {
                        "name": "Include Appendix F",
                        "identifier": "includeAppendixF",
                        "paramValue": true,
                        "type": "BOOLEAN"
                    },
        """
    break
    case 'Developer_Workbook':
        type = "ISSUE"
        reportDefinitionId = "8"
        inputReportParam = """
        {
            "name": "Key Terminology",
            "identifier": "IncludeSectionDescriptionOfKeyTerminology",
            "paramValue": true,
            "type": "BOOLEAN"
        },
        {
            "name": "About Fortify Solutions",
            "identifier": "IncludeSectionAboutFortifySecurity",
            "paramValue": true,
            "type": "BOOLEAN"
        },
        """
    break
    case 'Vulnerability_Report':
        type = "ISSUE"
        reportDefinitionId = "9"
        inputReportParam = ""
    break
    }

    def reportName = reportType + "-" + config.app_name + "_" + config.app_version + '-'+this.currentDateTime('yyyyMMddHHmmss')
    def cmd= """
        curl --location '${config.BASE_SSC_API_URL}/reports' \
            --header 'Authorization: ${authorization}' \
            --header 'Content-Type: application/json' \
            --data '{
                "name": "${reportName}",
                "note": "Auto generate by jte",
                "format": "PDF",
                "inputReportParameters": [
                    ${inputReportParam}
                    {
                        "name": "Application Version",
                        "identifier": "projectversionid",
                        "paramValue": ${appId},
                        "type": "SINGLE_PROJECT"
                    }
                ],
                "reportDefinitionId": ${reportDefinitionId},
                "type": "${type}",
                "project": {
                    "id": ${appId},
                    "name": "${config.app_version}",
                    "version": {
                        "id": ${applicationId},
                        "name": "${config.app_name}"
                    }
                }
            }'
    """

    def strReportDetail = this.runsh(steps, cmd, true)
    def reportDetail = this.jsonToObject(strReportDetail)
    def result = [
        "id": reportDetail.data.id ,
        "name" : reportDetail.data.name
        ]
    return result
}

def processReport(reportId, reportName,config){
    def statusReport  = this.getReportStatus(reportId, config)
    steps.echo  'Status Report : ' + statusReport.toString()
    while ( statusReport != 'PROCESS_COMPLETE') {
        Thread.sleep(20000)
        statusReport = this.getReportStatus(reportId, config)
        steps.echo  'Status Report : ' + statusReport.toString()
    }

    def token = this.generateFileToken(config)
    def reportLocation = this.downloadReport(reportId, token, reportName, config)
    return reportLocation
}

def generateFileToken(config){
    def auth = 'FortifyToken ' + this.getCredentials('SSC_CI_TOKEN_API')
    def url = config.BASE_SSC_API_URL+'/fileTokens'
    def cmd = """
        curl -s \
        --location "${url}" \
        --header "Authorization:  ${auth}" \
        --header 'Content-Type: application/json' \
        --header 'Accept: application/json' \
        --data '{
            "fileTokenType": 3
        }'
    """
    def strFileToken = this.runsh(steps,cmd,true)
    def fileToken = this.jsonToObject(strFileToken)
    return fileToken.data.token
}

def downloadReport(reportId, token, reportName, config){
    String urldownload=config.BASE_SSC_URL+'/transfer/reportDownload.html?mat='+token+'&id='+reportId
    reportName = reportName+'.pdf'
    def localdir = config.REPORT_DIR+'/'+reportName
    def file = new FileOutputStream(localdir)
    def out = new BufferedOutputStream(file)
    out << new URL(urldownload).openStream()
    out.close()

    steps.echo 'Report Location :'+localdir
    return localdir
}

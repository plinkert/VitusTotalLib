import requests, sys, warnings

def apiMeth(method, path, apikey, param = None):

    warnings.filterwarnings("ignore")

    APIURL = 'https://www.virustotal.com/vtapi/v2/'
    params = {'apikey': apikey}
    params.update(param)

    s = requests.Session()
    s.verify = False
    try:
        if method == "POST":
            r = s.post(APIURL+path, params = params)
        elif method == "GET":
            r = s.get(APIURL+path, params = params)
        else:
            return -1
        s.close()
        return r
    except:
        print("Nieobsługiwany błąd:", sys.exc_info()[0])
        raise

def apiResponse(response):
    if response.status_code == 200:
        if response.json()['response_code'] == -1 or response.json()['response_code'] == 0:
            return "Return code 200 - Response code "+ str(response.json()['response_code']) + ': ' + str(response.json()['verbose_msg'])
        else:
            return response.json()
    elif response.status_code == 204:
        return 'Response status code 204: Request rate limit exceeded. You are making more requests than allowed. You have exceeded one of your quotas (minute, daily or monthly). Daily quotas are reset every day at 00:00 UTC.'
    elif response.status_code == 400:
        return 'Response status code 400: Bad request. Your request was somehow incorrect. This can be caused by missing arguments or arguments with wrong values.'
    elif response.status_code == 403:
        return "Response status code 403: Forbidden. You don't have enough privileges to make the request. You may be doing a request without providing an API key or you may be making a request to a Private API without having the appropriate privileges"


class File:

    def __init__(self, apikey, resource):
        self.apikey = apikey
        self.resource = resource
        self.data = self.fileReport(self.apikey, self.resource)
        if self.data.status_code == 200 and self.data.json()['response_code'] == 1:
            self.error = 0
        else:
            self.error = apiResponse(self.data)

    def fileReport(self, apikey, resource):
        '''

        :param resource: MD5, SHA-1 or SHA-256 of a file for which you want to retrieve
        '''
        param = {}
        path = 'file/report'
        param['resource'] = resource
        return apiMeth("GET", path, apikey, param=param)

    def permalink(self):
        if self.error == 0:
            return{'Permalink' : self.data.json()['permalink']}
        else:
            return{'Error' : self.error}

    def hashMD5(self):
        if self.error == 0:
            return{'MD5' : self.data.json()['md5']}
        else:
            return{'Error' : self.error}

    def hashSHA1(self):
        if self.error == 0:
            return{'SHA1' : self.data.json()['sha1']}
        else:
            return{'Error' : self.error}

    def hashSHA256(self):
        if self.error == 0:
            return{'SHA256' : self.data.json()['sha256']}
        else:
            return{'Error' : self.error}

    def score(self):
        if self.error == 0:
            return{'Score' : str(self.data.json()['positives']) + '/' + str(self.data.json()['total'])}
        else:
            return{'Error' : self.error}

    def hashs(self):
        if self.error == 0:
            data = {}
            data.update(self.hashMD5())
            data.update(self.hashSHA1())
            data.update(self.hashSHA256())
            print(data)
            return data
        else:
            return {'Error' : self.error}


class URL:

    def __init__(self, apikey, resource):
        self.apikey = apikey
        self.resource = resource
        self.data = self.urlReport(apikey, self.resource)
        if self.data.status_code == 200 and self.data.json()['response_code'] == 1:
            self.error = 0
        else:
            self.error = apiResponse(self.data)

    def urlReport(self, apikey, resource):
        '''

        :param resource: URL
        '''
        param = {}
        path = 'url/report'
        param['resource'] = resource
        return apiMeth("GET", path, apikey, param=param)

    def permalink(self):
        if self.error == 0:
            return{'Permalink' : self.data.json()['permalink']}
        else:
            return{'Error' : self.error}

    def score(self):
        if self.error == 0:
            return {'Score': str(self.data.json()['positives']) + '/' + str(self.data.json()['total'])}
        else:
            return {'Error': self.error}

    def url(self):
        if self.error == 0:
            return {'URL' : self.data.json()['url']}
        else:
            return {'Error': self.error}

class IP:

    def __init__(self, apikey, resource):
        self.apikey = apikey
        self.ip = resource
        self.data = self.ipReport(apikey, self.ip)
        if self.data.status_code == 200 and self.data.json()['response_code'] == 1:
            self.error = 0
        else:
            self.error = apiResponse(self.data)

    def ipReport(self, apikey, resource):
        '''

        :param resource: IP adres
        '''
        param = {}
        path = 'ip-address/report'
        param['ip'] = resource
        return apiMeth("GET", path, apikey, param=param)

    def url(self):
        if self.error == 0 and self.data.json()['detected_urls'] != None:
            return {'URLs' : self.data.json()['detected_urls']}
        else:
            return {'Error': str(self.error) + "No URLs"}

    def country(self):
        if self.error == 0:
            return {'Country' : self.data.json()['country']}
        else:
            return {'Error': self.error}

    def owner(self):
        if self.error == 0:
            if 'as_owner' in self.data.json():
                return {'Owner' : self.data.json()['as_owner']}
            else:
                return {'Owner' : '-------------'}
        else:
            return {'Error': self.error}

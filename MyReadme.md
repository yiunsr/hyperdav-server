
* https://blog.naver.com/jackylim/100109039688

* Request 
```xml
PROPFIND /idc/idcplg/webdav/Contribution%20Folders/Documents1/ HTTP/1.1
Host: www.foo.com
Content-Type: text/xml; charset="utf-8"
Content-Length: xxxx

 
<?xml version="1.0" encoding="utf-8" ?>
  <d:propfind xmlns:d="DAV :"  xmlns:i="IDC:">
    <d:prop >
      <d:ishidden/>
      <d:isreadonly/>
      <d:getcontentlength/>
      <d:iscollection/>
      <d:isfolder/>
      <d:getcontenttype/>
      <d:creationdate/>
      <d:displayname/>
      <i:displayas/>
    </d:prop>
  </d:propfind>
```

* Response 

```xml
HTTP/1.1 207 Multi-Status
Content-Type: text/xml; charset="utf-8"
Content-Length: xxxx

<?xml version="1.0" encoding="utf-8" ?>
  <d:multistatus xmlns="DAV:"  xmlns:d="DAV:"  xmlns:i="IDC:">
    <d:response>
      <d:href>/idc/idcplg/webdav/Contribution%20Folders/Documents1/</d:href>
      <d:propstat>
        <d:prop>
          <d:ishidden>0</d:ishidden>
          <d:isreadonly>0</d:isreadonly>
          <d:getcontentlength>0</d:getcontentlength>
          <d:iscollection>1</d:iscollection>
          <d:isfolder>1</d:isfolder>
          <d:getcontenttype>httpd/unix-directory</d:getcontenttype>
          <d:creationdate>2010-07-12T02:06:00Z</d:creationdate>
          <d:displayname>Documents1</d:displayname>
          <i:displayas>Documents1</i:displayas>
        </d:prop>
        <d:status>HTTP/1.1 200 OK</d:status>
      </d:propstat>
    </d:response>
  </d:multistatus>

```


* http://www.webdav.org/specs/rfc2518.html
* 
## DAV Properties
* creationdate
* displayname
* getcontentlanguage
  * 필수는 아닌 것 같음
* getcontentlength
* getcontenttype
* getetag
* getlastmodified
* lockdiscovery
* resourcetype
* source
  * 필수는 아닌 것 같음
* supportedlock
  * 필수는 아님
  
### 정의가 필요한 것
* creationdate
* displayname
* getcontentlength
* getcontenttype
* getetag
* getlastmodified
* resourcetype


### PROPFIND Method
* https://learn.microsoft.com/en-us/previous-versions/office/developer/exchange-server-2003/aa142960(v=exchg.65)


### PC버전 vscode 디버깅 
* vscode 에서 한국어 로그가 깨지는 경우 터미널에 아래 설정을 한다. 
```
chcp 65001
```
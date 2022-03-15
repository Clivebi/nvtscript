if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882522" );
	script_version( "$Revision: 14095 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-11 14:54:56 +0100 (Mon, 11 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-07-19 05:26:54 +0200 (Tue, 19 Jul 2016)" );
	script_cve_id( "CVE-2016-5387" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for httpd CESA-2016:1421 centos6" );
	script_tag( name: "summary", value: "Check the version of httpd" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The httpd packages provide the Apache HTTP
Server, a powerful, efficient, and extensible web server.

Security Fix(es):

  * It was discovered that httpd used the value of the Proxy header from HTTP
requests to initialize the HTTP_PROXY environment variable for CGI scripts,
which in turn was incorrectly used by certain HTTP client implementations
to configure the proxy for outgoing HTTP requests. A remote attacker could
possibly use this flaw to redirect HTTP requests performed by a CGI script
to an attacker-controlled proxy via a malicious HTTP request.
(CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the Proxy
request header to scripts via the HTTP_PROXY environment variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this issue.

4. Solution:

For details on how to apply this update, which includes the changes
described in this advisory, refer to the linked article.

After installing the updated packages, the httpd daemon will be restarted
automatically.

5. Bugs fixed:

1353755 - CVE-2016-5387 Apache HTTPD: sets environmental variable based on user supplied Proxy request header

6. Package List:

Red Hat Enterprise Linux Desktop (v. 5 client):

Source:
httpd-2.2.3-92.el5_11.src.rpm

i386:
httpd-2.2.3-92.el5_11.i386.rpm
httpd-debuginfo-2.2.3-92.el5_11.i386.rpm
mod_ssl-2.2.3-92.el5_11.i386.rpm

x86_64:
httpd-2.2.3-92.el5_11.x86_64.rpm
httpd-debuginfo-2.2.3-92.el5_11.x86_64.rpm
mod_ssl-2.2.3-92.el5_11.x86_64.rpm

Red Hat Enterprise Linux Desktop Workstation (v. 5 client):

Source:
httpd-2.2.3-92.el5_11.src.rpm

i386:
httpd-debuginfo-2.2.3-92.el5_11.i386.rpm
httpd-devel-2.2.3-92.el5_11.i386.rpm
httpd-manual-2.2.3-92.el5_11.i386.rpm

x86_64:
httpd-debuginfo-2.2.3-92.el5_11.i386.rpm
httpd-debuginfo-2.2.3-92.el5_11.x86_64.rpm
httpd-devel-2.2.3-92.el5_11.i386.rpm
httpd-devel-2.2.3-92.el5_11.x86_64.rpm
httpd-manual-2.2.3-92.el5_11.x86_64.rpm

Red Hat Enterprise Linux (v. 5 server):

Source:
httpd-2.2.3-92.el5_11.src.rpm

i386:
httpd-2.2.3-92.el5_11.i386.rpm
httpd-debuginfo-2.2.3-92.el5_11.i386.rpm
httpd-devel-2.2.3-92.el5_11.i386.rpm
httpd-manual-2.2.3-92.el5_11.i386.rpm
mod_ssl-2.2.3-92.el5_11.i386.rpm

ia64:
httpd-2.2.3-92.el5_11.ia64.rpm
httpd-debuginfo-2.2.3-92.el5_11.ia64.rpm
httpd-devel-2.2.3-92.el5_11.ia64.rpm
httpd-manual-2.2.3-92.el5_11.ia64.rpm
mod_ssl-2.2.3-92.el5_11.ia64.rpm

ppc:
httpd-2.2.3-92.el5_11.ppc.rpm
httpd-debuginfo-2.2.3-92.el5_11.ppc.rpm
httpd-debug ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "httpd on CentOS 6" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1421" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-July/021980.html" );
	script_xref( name: "URL", value: "https://access.redhat.com/articles/11258" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "httpd", rpm: "httpd~2.2.15~54.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-devel", rpm: "httpd-devel~2.2.15~54.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-manual", rpm: "httpd-manual~2.2.15~54.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "httpd-tools", rpm: "httpd-tools~2.2.15~54.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "mod_ssl", rpm: "mod_ssl~2.2.15~54.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882545" );
	script_version( "2019-12-18T09:57:42+0000" );
	script_tag( name: "last_modification", value: "2019-12-18 09:57:42 +0000 (Wed, 18 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-08-19 05:37:22 +0200 (Fri, 19 Aug 2016)" );
	script_cve_id( "CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5699" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for python CESA-2016:1626 centos7" );
	script_tag( name: "summary", value: "Check the version of python" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to many
system calls and libraries, as well as to various windowing systems.

Security Fix(es):

  * It was discovered that the Python CGIHandler class did not properly
protect against the HTTP_PROXY variable name clash in a CGI context. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a Python CGI script to an attacker-controlled proxy via a
malicious HTTP request. (CVE-2016-1000110)

  * It was found that Python's smtplib library did not return an exception
when StartTLS failed to be established in the SMTP.starttls() function. A
man in the middle attacker could strip out the STARTTLS command without
generating an exception on the Python SMTP client application, preventing
the establishment of the TLS layer. (CVE-2016-0772)

  * It was found that the Python's httplib library (used by urllib, urllib2
and others) did not properly check HTTPConnection.putheader() function
arguments. An attacker could use this flaw to inject additional headers in
a Python application that allowed user provided header names or values.
(CVE-2016-5699)

Red Hat would like to thank Scott Geary (VendHQ) for reporting
CVE-2016-1000110." );
	script_tag( name: "affected", value: "python on CentOS 7" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "CESA", value: "2016:1626" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2016-August/022038.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "python", rpm: "python~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-debug", rpm: "python-debug~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-devel", rpm: "python-devel~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-libs", rpm: "python-libs~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-test", rpm: "python-test~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "python-tools", rpm: "python-tools~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "tkinter", rpm: "tkinter~2.7.5~38.el7_2", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


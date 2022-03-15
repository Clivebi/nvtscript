if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72168" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2012-3435" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-09-15 04:23:46 -0400 (Sat, 15 Sep 2012)" );
	script_name( "Debian Security Advisory DSA 2539-1 (zabbix)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202539-1" );
	script_tag( name: "insight", value: "It was discovered that Zabbix, a network monitoring solution, does not
properly validate user input used as a part of an SQL query. This may
allow unauthenticated attackers to execute arbitrary SQL commands (SQL
injection) and possibly escalate privileges.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.8.2-1squeeze4.

For the testing distribution (wheezy), this problem will be fixed soon.

For the unstable distribution (sid), this problem has been fixed in
version 1:2.0.2+dfsg-1." );
	script_tag( name: "solution", value: "We recommend that you upgrade your zabbix packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to zabbix
announced via advisory DSA 2539-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "zabbix-agent", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-frontend-php", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-proxy-mysql", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-proxy-pgsql", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-server-mysql", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "zabbix-server-pgsql", ver: "1:1.8.2-1squeeze4", rls: "DEB6" ) ) != NULL){
	report += res;
}
if( report != "" ){
	security_message( data: report );
}
else {
	if(__pkg_match){
		exit( 99 );
	}
}


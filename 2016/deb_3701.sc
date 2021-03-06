if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.703701" );
	script_version( "$Revision: 14279 $" );
	script_cve_id( "CVE-2016-1247" );
	script_name( "Debian Security Advisory DSA 3701-1 (nginx - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:48:34 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-10-25 00:00:00 +0200 (Tue, 25 Oct 2016)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2016/dsa-3701.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB8" );
	script_tag( name: "affected", value: "nginx on Debian Linux" );
	script_tag( name: "solution", value: "For the stable distribution (jessie),
this problem has been fixed in version 1.6.2-5+deb8u3.

We recommend that you upgrade your nginx packages." );
	script_tag( name: "summary", value: "Dawid Golunski reported the nginx web
server packages in Debian suffered from a privilege escalation vulnerability
(www-data to root) due to the way log files are handled. This security update changes
ownership of the /var/log/nginx directory root. In addition,
/var/log/nginx has to be made accessible to local users, and local
users may be able to read the log files themselves local until the
next logrotate invocation." );
	script_tag( name: "vuldetect", value: "This check tests the installed software
version using the apt package manager." );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "nginx", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-common", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-doc", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-extras-dbg", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-full-dbg", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "nginx-light-dbg", ver: "1.6.2-5+deb8u3", rls: "DEB8" ) ) != NULL){
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


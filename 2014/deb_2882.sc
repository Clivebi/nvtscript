if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.702882" );
	script_version( "$Revision: 14302 $" );
	script_cve_id( "CVE-2013-5951" );
	script_name( "Debian Security Advisory DSA 2882-1 (extplorer - security update)" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 09:28:48 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-03-20 00:00:00 +0100 (Thu, 20 Mar 2014)" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_xref( name: "URL", value: "http://www.debian.org/security/2014/dsa-2882.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2014 Greenbone Networks GmbH http://greenbone.net" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB(6|7)" );
	script_tag( name: "affected", value: "extplorer on Debian Linux" );
	script_tag( name: "solution", value: "For the oldstable distribution (squeeze), this problem has been fixed in
version 2.1.0b6+dfsg.2-1+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2.1.0b6+dfsg.3-4+deb7u1.

For the unstable distribution (sid), this problem will be fixed soon.

We recommend that you upgrade your extplorer packages." );
	script_tag( name: "summary", value: "Multiple cross-site scripting (XSS) vulnerabilities have been discovered
in extplorer, a web file explorer and manager using Ext JS.
A remote attacker can inject arbitrary web script or HTML code via a
crafted string in the URL to application.js.php, admin.php, copy_move.php,
functions.php, header.php and upload.php." );
	script_tag( name: "vuldetect", value: "This check tests the installed software version using the apt package manager." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "extplorer", ver: "2.1.0b6+dfsg.2-1+squeeze2", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "extplorer", ver: "2.1.0b6+dfsg.3-4+deb7u1", rls: "DEB7" ) ) != NULL){
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


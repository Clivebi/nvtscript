if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.68980" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-07 16:04:02 +0100 (Mon, 07 Mar 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-4329", "CVE-2010-4480", "CVE-2010-4481" );
	script_name( "Debian Security Advisory DSA 2139-1 (phpmyadmin)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202139-1" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in phpMyAdmin, a tool
to administer MySQL over the web. The Common Vulnerabilities and Exposures
project identifies the following problems:

CVE-2010-4329

Cross site scripting was possible in search, that allowed
a remote attacker to inject arbitrary web script or HTML.

CVE-2010-4480

Cross site scripting was possible in errors, that allowed
a remote attacker to inject arbitrary web script or HTML.

CVE-2010-4481

Display of PHP's phpinfo() function was available to world, but only
if this functionality had been enabled (defaults to off). This may
leak some information about the host system.

For the stable distribution (lenny), these problems have been fixed in
version 2.11.8.1-5+lenny7.

For the testing (squeeze) and unstable distribution (sid), these problems
have been fixed in version 3.3.7-3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your phpmyadmin package." );
	script_tag( name: "summary", value: "The remote host is missing an update to phpmyadmin
announced via advisory DSA 2139-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "phpmyadmin", ver: "2.11.8.1-5+lenny7", rls: "DEB5" ) ) != NULL){
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


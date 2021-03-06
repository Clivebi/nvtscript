if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69106" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-03-09 05:54:11 +0100 (Wed, 09 Mar 2011)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_cve_id( "CVE-2010-2795", "CVE-2010-2796", "CVE-2010-3690", "CVE-2010-3691", "CVE-2010-3692" );
	script_name( "Debian Security Advisory DSA 2172-1 (moodle)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB5" );
	script_tag( name: "insight", value: "Several vulnerabilities have been discovered in phpCAS, a CAS client
  library for PHP. The Moodle course management system includes a copy of phpCAS." );
	script_tag( name: "summary", value: "The remote host is missing an update to moodle
  announced via advisory DSA 2172-1." );
	script_tag( name: "solution", value: "For the oldstable distribution (lenny), this problem has been fixed in
  version 1.8.13-3.

  The stable distribution (squeeze) already contains a fixed version of
  phpCAS.

  The unstable distribution (sid) already contains a fixed version of
  phpCAS.

  We recommend that you upgrade your moodle packages." );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202172-1" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "moodle", ver: "1.8.13-3", rls: "DEB5" ) ) != NULL){
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


if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.69967" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-08-03 04:36:20 +0200 (Wed, 03 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Debian Security Advisory DSA 2262-1 (moodle)" );
	script_cve_id( "CVE-2011-4133", "CVE-2011-4278", "CVE-2011-4283", "CVE-2011-4286", "CVE-2011-4288", "CVE-2011-4290" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202262-1" );
	script_tag( name: "insight", value: "Several cross-site scripting and information disclosure issues have
been fixed in Moodle, a course management system for online learning:

  * MSA-11-0002 Cross-site request forgery vulnerability in RSS block

  * MSA-11-0003 Cross-site scripting vulnerability in tag autocomplete

  * MSA-11-0008 IMS enterprise enrolment file may disclose sensitive
information

  * MSA-11-0011 Multiple cross-site scripting problems in media filter

  * MSA-11-0015 Cross Site Scripting through URL encoding

  * MSA-11-0013 Group/Quiz permissions issue

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.9.dfsg2-2.1+squeeze1.

For the unstable distribution (sid), this problem has been fixed in
version 1.9.9.dfsg2-3." );
	script_tag( name: "solution", value: "We recommend that you upgrade your moodle packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to moodle
announced via advisory DSA 2262-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "moodle", ver: "1.9.9.dfsg2-2.1+squeeze1", rls: "DEB6" ) ) != NULL){
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


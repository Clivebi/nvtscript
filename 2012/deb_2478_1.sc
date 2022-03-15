if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.71356" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2012-2337" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-05-31 11:51:43 -0400 (Thu, 31 May 2012)" );
	script_name( "Debian Security Advisory DSA 2478-1 (sudo)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202478-1" );
	script_tag( name: "insight", value: "It was discovered that sudo misparsed network masks used in Host and
Host_List stanzas. This allowed the execution of commands on hosts,
where the user would not be allowed to run the specified command.

For the stable distribution (squeeze), this problem has been fixed in
version 1.7.4p4-2.squeeze.3.

For the unstable distribution (sid), this problem will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your sudo packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to sudo
announced via advisory DSA 2478-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "sudo", ver: "1.7.4p4-2.squeeze.3", rls: "DEB6" ) ) != NULL){
	report += res;
}
if(( res = isdpkgvuln( pkg: "sudo-ldap", ver: "1.7.4p4-2.squeeze.3", rls: "DEB6" ) ) != NULL){
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


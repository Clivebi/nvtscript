if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.72474" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2012-4445" );
	script_version( "$Revision: 14275 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-18 15:39:45 +0100 (Mon, 18 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-10-13 02:34:33 -0400 (Sat, 13 Oct 2012)" );
	script_name( "Debian Security Advisory DSA 2557-1 (hostapd)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB6" );
	script_xref( name: "URL", value: "https://secure1.securityspace.com/smysecure/catid.html?in=DSA%202557-1" );
	script_tag( name: "insight", value: "Timo Warns discovered that the internal authentication server of hostapd,
a user space IEEE 802.11 AP and IEEE 802.1X/WPA/WPA2/EAP Authenticator,
is vulnerable to a buffer overflow when processing fragmented EAP-TLS
messages.  As a result, an internal overflow checking routine terminates
the process.  An attacker can abuse this flaw to conduct denial of service
attacks via crafted EAP-TLS messages prior to any authentication.

For the stable distribution (squeeze), this problem has been fixed in
version 0.6.10-2+squeeze1.

For the testing (wheezy) and unstable (sid) distributions, this problem
will be fixed soon." );
	script_tag( name: "solution", value: "We recommend that you upgrade your hostapd packages." );
	script_tag( name: "summary", value: "The remote host is missing an update to hostapd
announced via advisory DSA 2557-1." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(( res = isdpkgvuln( pkg: "hostapd", ver: "1:0.6.10-2+squeeze1", rls: "DEB6" ) ) != NULL){
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


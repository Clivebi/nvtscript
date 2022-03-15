if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842167" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2015-04-14 07:18:57 +0200 (Tue, 14 Apr 2015)" );
	script_cve_id( "CVE-2015-1798", "CVE-2015-1799" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:M/Au:N/C:N/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ntp USN-2567-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Miroslav Lichvar discovered that NTP
incorrectly validated MAC fields. A remote attacker could possibly use this issue
to bypass authentication and spoof packets. (CVE-2015-1798)

Miroslav Lichvar discovered that NTP incorrectly handled certain invalid
packets. A remote attacker could possibly use this issue to cause a denial
of service. (CVE-2015-1799)

Juergen Perlinger discovered that NTP incorrectly generated MD5 keys on
big-endian platforms. This issue could either cause ntp-keygen to hang, or
could result in non-random keys. (CVE number pending)" );
	script_tag( name: "affected", value: "ntp on Ubuntu 14.10,
  Ubuntu 14.04 LTS,
  Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2567-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2567-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.10|14\\.04 LTS|12\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.10"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu2.14.10.3", rls: "UBUNTU14.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu2.14.04.3", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p3+dfsg-1ubuntu3.4", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


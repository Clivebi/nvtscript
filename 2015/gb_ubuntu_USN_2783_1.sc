if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842504" );
	script_version( "2020-06-23T09:25:46+0000" );
	script_tag( name: "last_modification", value: "2020-06-23 09:25:46 +0000 (Tue, 23 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-10-28 07:18:08 +0100 (Wed, 28 Oct 2015)" );
	script_cve_id( "CVE-2015-5146", "CVE-2015-5194", "CVE-2015-5195", "CVE-2015-7703", "CVE-2015-5219", "CVE-2015-5300", "CVE-2015-7691", "CVE-2015-7692", "CVE-2015-7702", "CVE-2015-7701", "CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7850", "CVE-2015-7852", "CVE-2015-7853", "CVE-2015-7855", "CVE-2015-7871" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for ntp USN-2783-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ntp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Aleksis Kauppinen discovered that NTP
incorrectly handled certain remote config packets. In a non-default configuration,
a remote authenticated attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service. (CVE-2015-5146)

Miroslav Lichvar discovered that NTP incorrectly handled logconfig
directives. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service. (CVE-2015-5194)

Miroslav Lichvar discovered that NTP incorrectly handled certain statistics
types. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service. (CVE-2015-5195)

Miroslav Lichvar discovered that NTP incorrectly handled certain file
paths. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to crash, resulting in a denial
of service, or overwrite certain files. (CVE-2015-7703)

Miroslav Lichvar discovered that NTP incorrectly handled certain packets.
A remote attacker could possibly use this issue to cause NTP to hang,
resulting in a denial of service. (CVE-2015-5219)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP
incorrectly handled restarting after hitting a panic threshold. A remote
attacker could possibly use this issue to alter the system time on clients.
(CVE-2015-5300)

It was discovered that NTP incorrectly handled autokey data packets. A
remote attacker could possibly use this issue to cause NTP to crash,
resulting in a denial of service, or possibly execute arbitrary code.
(CVE-2015-7691, CVE-2015-7692, CVE-2015-7702)

It was discovered that NTP incorrectly handled memory when processing
certain autokey messages. A remote attacker could possibly use this issue
to cause NTP to consume memory, resulting in a denial of service.
(CVE-2015-7701)

Aanchal Malhotra, Isaac E. Cohen, and Sharon Goldberg discovered that NTP
incorrectly handled rate limiting. A remote attacker could possibly use
this issue to cause clients to stop updating their clock. (CVE-2015-7704,
CVE-2015-7705)

Yves Younan discovered that NTP incorrectly handled logfile and keyfile
directives. In a non-default configuration, a remote authenticated attacker
could possibly use this issue to cause NTP to enter a loop, resulting in a
denial of service. (CVE-2015-7850)

Yves Younan and Aleksander Nikolich discovered that NTP incorrectly handled
ascii conversion. A remote attacker could possibly  ...

  Description truncated, please see the referenced URL(s) for more information." );
	script_tag( name: "affected", value: "ntp on Ubuntu 15.10, Ubuntu 15.04, Ubuntu 14.04 LTS, Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2783-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2783-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(15\\.04|14\\.04 LTS|12\\.04 LTS|15\\.10)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU15.04"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu6.2", rls: "UBUNTU15.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu2.14.04.5", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p3+dfsg-1ubuntu3.6", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU15.10"){
	if(( res = isdpkgvuln( pkg: "ntp", ver: "1:4.2.6.p5+dfsg-3ubuntu8.1", rls: "UBUNTU15.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


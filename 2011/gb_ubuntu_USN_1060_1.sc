if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1060-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840582" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-11 13:26:17 +0100 (Fri, 11 Feb 2011)" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1060-1" );
	script_cve_id( "CVE-2010-2023", "CVE-2010-2024", "CVE-2010-4345", "CVE-2011-0017" );
	script_name( "Ubuntu Update for exim4 vulnerabilities USN-1060-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(9\\.10|6\\.06 LTS|10\\.04 LTS|8\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1060-1" );
	script_tag( name: "affected", value: "exim4 vulnerabilities on Ubuntu 6.06 LTS,
  Ubuntu 8.04 LTS,
  Ubuntu 9.10,
  Ubuntu 10.04 LTS,
  Ubuntu 10.10" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "It was discovered that Exim contained a design flaw in the way it processed
  alternate configuration files. An attacker that obtained privileges of the
  'Debian-exim' user could use an alternate configuration file to obtain
  root privileges. (CVE-2010-4345)

  It was discovered that Exim incorrectly handled certain return values when
  handling logging. A local attacker could use this flaw to obtain root
  privileges. (CVE-2011-0017)

  Dan Rosenberg discovered that Exim incorrectly handled writable sticky-bit
  mail directories. If Exim were configured in this manner, a local user
  could use this flaw to cause a denial of service or possibly gain
  privileges. This issue only applied to Ubuntu 6.06 LTS, 8.04 LTS, 9.10,
  and 10.04 LTS. (CVE-2010-2023)

  Dan Rosenberg discovered that Exim incorrectly handled MBX locking. If
  Exim were configured in this manner, a local user could use this flaw to
  cause a denial of service or possibly gain privileges. This issue only
  applied to Ubuntu 6.06 LTS, 8.04 LTS, 9.10, and 10.04 LTS. (CVE-2010-2024)" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU9.10"){
	if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4", ver: "4.69-11ubuntu4.2", rls: "UBUNTU9.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU6.06 LTS"){
	if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4", ver: "4.60-3ubuntu3.3", rls: "UBUNTU6.06 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4", ver: "4.71-3ubuntu1.1", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4", ver: "4.69-2ubuntu0.3", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "exim4-base", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy-dbg", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-heavy", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light-dbg", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-daemon-light", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dbg", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-dev", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "eximon4", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4-config", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "exim4", ver: "4.72-1ubuntu1.1", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


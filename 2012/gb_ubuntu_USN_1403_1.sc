if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1403-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840959" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-03-26 14:17:20 +0530 (Mon, 26 Mar 2012)" );
	script_cve_id( "CVE-2012-1126", "CVE-2012-1127", "CVE-2012-1128", "CVE-2012-1129", "CVE-2012-1130", "CVE-2012-1131", "CVE-2012-1132", "CVE-2012-1133", "CVE-2012-1134", "CVE-2012-1135", "CVE-2012-1136", "CVE-2012-1137", "CVE-2012-1138", "CVE-2012-1139", "CVE-2012-1140", "CVE-2012-1141", "CVE-2012-1142", "CVE-2012-1143", "CVE-2012-1144" );
	script_xref( name: "USN", value: "1403-1" );
	script_name( "Ubuntu Update for freetype USN-1403-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.10|10\\.04 LTS|11\\.10|11\\.04|8\\.04 LTS)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1403-1" );
	script_tag( name: "affected", value: "freetype on Ubuntu 11.10,
  Ubuntu 11.04,
  Ubuntu 10.10,
  Ubuntu 10.04 LTS,
  Ubuntu 8.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1126)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1127)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1128)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type42 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1129)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed PCF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash. (CVE-2012-1130)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1131)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type1 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1132)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed BDF font files. If a user were tricked into using a specially crafted
  font file, a remote attacker could cause FreeType to crash or possibly execute
  arbitrary code with user privileges. (CVE-2012-1133)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed Type1 font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash or possibly
  execute arbitrary code with user privileges. (CVE-2012-1134)

  Mateusz Jurczyk discovered that FreeType did not correctly handle certain
  malformed TrueType font files. If a user were tricked into using a specially
  crafted font file, a remote attacker could cause FreeType to crash.
  (CVE-2012-1135)

  Mateusz Jurczyk discovere ...

  Description truncated, please see the referenced URL(s) for more information." );
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
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.2-2ubuntu0.4", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.3.11-1ubuntu2.6", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.10"){
	if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.4-2ubuntu1.2", rls: "UBUNTU11.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU11.04"){
	if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.4.4-1ubuntu2.3", rls: "UBUNTU11.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU8.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libfreetype6", ver: "2.3.5-1ubuntu4.8.04.9", rls: "UBUNTU8.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1320-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.840858" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2012-01-09 13:30:07 +0530 (Mon, 09 Jan 2012)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1320-1" );
	script_cve_id( "CVE-2011-3504", "CVE-2011-4351", "CVE-2011-4352", "CVE-2011-4353", "CVE-2011-4364", "CVE-2011-4579" );
	script_name( "Ubuntu Update for ffmpeg USN-1320-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(10\\.04 LTS|10\\.10)" );
	script_tag( name: "summary", value: "Ubuntu Update for Linux kernel vulnerabilities USN-1320-1" );
	script_tag( name: "affected", value: "ffmpeg on Ubuntu 10.10,
  Ubuntu 10.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Steve Manzuik discovered that FFmpeg incorrectly handled certain malformed
  Matroska files. If a user were tricked into opening a crafted Matroska
  file, an attacker could cause a denial of service via application crash, or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. (CVE-2011-3504)

  Phillip Langlois discovered that FFmpeg incorrectly handled certain
  malformed QDM2 streams. If a user were tricked into opening a crafted QDM2
  stream file, an attacker could cause a denial of service via application
  crash, or possibly execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2011-4351)

  Phillip Langlois discovered that FFmpeg incorrectly handled certain
  malformed VP3 streams. If a user were tricked into opening a crafted file,
  an attacker could cause a denial of service via application crash, or
  possibly execute arbitrary code with the privileges of the user invoking
  the program. This issue only affected Ubuntu 10.10. (CVE-2011-4352)

  Phillip Langlois discovered that FFmpeg incorrectly handled certain
  malformed VP5 and VP6 streams. If a user were tricked into opening a
  crafted file, an attacker could cause a denial of service via application
  crash, or possibly execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2011-4353)

  It was discovered that FFmpeg incorrectly handled certain malformed VMD
  files. If a user were tricked into opening a crafted VMD file, an attacker
  could cause a denial of service via application crash, or possibly execute
  arbitrary code with the privileges of the user invoking the program.
  (CVE-2011-4364)

  Phillip Langlois discovered that FFmpeg incorrectly handled certain
  malformed SVQ1 streams. If a user were tricked into opening a crafted SVQ1
  stream file, an attacker could cause a denial of service via application
  crash, or possibly execute arbitrary code with the privileges of the user
  invoking the program. (CVE-2011-4579)" );
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
if(release == "UBUNTU10.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.5.1-1ubuntu1.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.5.1-1ubuntu1.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU10.10"){
	if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.6-2ubuntu6.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.6-2ubuntu6.3", rls: "UBUNTU10.10" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


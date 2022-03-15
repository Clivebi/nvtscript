if(description){
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-1706-1/" );
	script_oid( "1.3.6.1.4.1.25623.1.0.841299" );
	script_version( "$Revision: 14132 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 10:25:59 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-01-31 09:26:54 +0530 (Thu, 31 Jan 2013)" );
	script_cve_id( "CVE-2012-2783", "CVE-2012-2803" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_xref( name: "USN", value: "1706-1" );
	script_name( "Ubuntu Update for ffmpeg USN-1706-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU10\\.04 LTS" );
	script_tag( name: "affected", value: "ffmpeg on Ubuntu 10.04 LTS" );
	script_tag( name: "insight", value: "It was discovered that FFmpeg incorrectly handled certain malformed media
  files. If a user were tricked into opening a crafted media file, an
  attacker could cause a denial of service via application crash, or possibly
  execute arbitrary code with the privileges of the user invoking the
  program." );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
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
	if(( res = isdpkgvuln( pkg: "libavcodec52", ver: "4:0.5.9-0ubuntu0.10.04.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libavformat52", ver: "4:0.5.9-0ubuntu0.10.04.3", rls: "UBUNTU10.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


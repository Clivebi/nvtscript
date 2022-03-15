if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843272" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2017-08-08 07:19:43 +0200 (Tue, 08 Aug 2017)" );
	script_cve_id( "CVE-2014-0250", "CVE-2014-0791", "CVE-2017-2834", "CVE-2017-2835", "CVE-2017-2836", "CVE-2017-2837", "CVE-2017-2838", "CVE-2017-2839" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for freerdp USN-3380-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freerdp'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that FreeRDP incorrectly
  handled certain width and height values. A malicious server could use this issue
  to cause FreeRDP to crash, resulting in a denial of service, or possibly execute
  arbitrary code. This issue only applied to Ubuntu 14.04 LTS. (CVE-2014-0250) It
  was discovered that FreeRDP incorrectly handled certain values in a Scope List.
  A malicious server could use this issue to cause FreeRDP to crash, resulting in
  a denial of service, or possibly execute arbitrary code. (CVE-2014-0791) Tyler
  Bohan discovered that FreeRDP incorrectly handled certain length values. A
  malicious server could use this issue to cause FreeRDP to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2017-2834,
  CVE-2017-2835) Tyler Bohan discovered that FreeRDP incorrectly handled certain
  packets. A malicious server could possibly use this issue to cause FreeRDP to
  crash, resulting in a denial of service. (CVE-2017-2836, CVE-2017-2837,
  CVE-2017-2838, CVE-2017-2839)" );
	script_tag( name: "affected", value: "freerdp on Ubuntu 17.04,
  Ubuntu 16.04 LTS,
  Ubuntu 14.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3380-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3380-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU(14\\.04 LTS|17\\.04|16\\.04 LTS)" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU14.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libfreerdp1:i386", ver: "1.0.2-2ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libfreerdp1:amd64", ver: "1.0.2-2ubuntu1.1", rls: "UBUNTU14.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU17.04"){
	if(( res = isdpkgvuln( pkg: "libfreerdp-client1.1:i386", ver: "1.1.0~git20140921.1.440916e+dfsg1-10ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libfreerdp-client1.1:amd64", ver: "1.1.0~git20140921.1.440916e+dfsg1-10ubuntu1.1", rls: "UBUNTU17.04" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libfreerdp-client1.1:i386", ver: "1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libfreerdp-client1.1:amd64", ver: "1.1.0~git20140921.1.440916e+dfsg1-5ubuntu1.2", rls: "UBUNTU16.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


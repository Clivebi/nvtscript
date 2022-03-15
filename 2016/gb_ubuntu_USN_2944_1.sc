if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.842705" );
	script_version( "$Revision: 14140 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-13 13:26:09 +0100 (Wed, 13 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-04-05 05:00:45 +0200 (Tue, 05 Apr 2016)" );
	script_cve_id( "CVE-2014-8541", "CVE-2015-1872", "CVE-2015-3395", "CVE-2015-5479", "CVE-2015-6818", "CVE-2015-6820", "CVE-2015-6824", "CVE-2015-6826", "CVE-2015-8364", "CVE-2015-8365", "CVE-2016-1897", "CVE-2016-1898", "CVE-2016-2326", "CVE-2016-2330" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for libav USN-2944-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libav'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that Libav incorrectly
  handled certain malformed media files. If a user were tricked into opening a
  crafted media file, an attacker could cause a denial of service via application
  crash, or possibly execute arbitrary code with the privileges of the user
  invoking the program." );
	script_tag( name: "affected", value: "libav on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "2944-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-2944-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=UBUNTU12\\.04 LTS" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "UBUNTU12.04 LTS"){
	if(( res = isdpkgvuln( pkg: "libavcodec53", ver: "4:0.8.17-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isdpkgvuln( pkg: "libavformat53", ver: "4:0.8.17-0ubuntu0.12.04.2", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


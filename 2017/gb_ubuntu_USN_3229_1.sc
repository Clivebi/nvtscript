if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843091" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-03-14 05:47:53 +0100 (Tue, 14 Mar 2017)" );
	script_cve_id( "CVE-2014-9601", "CVE-2016-9189", "CVE-2016-9190" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-01 01:30:00 +0000 (Sat, 01 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Ubuntu Update for python-imaging USN-3229-1" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'python-imaging'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the Python Imaging
  Library incorrectly handled certain compressed text chunks in PNG images. A
  remote attacker could possibly use this issue to cause the Python Imaging
  Library to crash, resulting in a denial of service. (CVE-2014-9601) Cris Neckar
  discovered that the Python Imaging Library incorrectly handled certain malformed
  images. A remote attacker could use this issue to cause the Python Imaging
  Library to crash, resulting in a denial of service, or possibly obtain sensitive
  information. (CVE-2016-9189) Cris Neckar discovered that the Python Imaging
  Library incorrectly handled certain malformed images. A remote attacker could
  use this issue to cause the Python Imaging Library to crash, resulting in a
  denial of service, or possibly execute arbitrary code. (CVE-2016-9190)" );
	script_tag( name: "affected", value: "python-imaging on Ubuntu 12.04 LTS" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "USN", value: "3229-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3229-1/" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isdpkgvuln( pkg: "python-imaging", ver: "1.1.7-4ubuntu0.12.04.3", rls: "UBUNTU12.04 LTS" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}


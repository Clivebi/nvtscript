if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843962" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2016-5684" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-28 20:29:00 +0000 (Thu, 28 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:41:00 +0000 (Wed, 03 Apr 2019)" );
	script_name( "Ubuntu Update for freeimage USN-3925-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU14\\.04 LTS|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3925-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3925-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'freeimage'
  package(s) announced via the USN-3925-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that an out-of-bounds
write vulnerability existed in the XMP Image handling functionality of the
FreeImage library. If a user or automated system were tricked into opening a
specially crafted image, a remote attacker could overwrite arbitrary memory,
resulting in code execution." );
	script_tag( name: "affected", value: "'freeimage' package(s) on Ubuntu 16.04 LTS, Ubuntu 14.04 LTS." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
release = dpkg_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "UBUNTU14.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.15.4-3ubuntu0.1", rls: "UBUNTU14.04 LTS" ) )){
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
	exit( 0 );
}
if(release == "UBUNTU16.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimage3", ver: "3.17.0+ds1-2ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libfreeimageplus3", ver: "3.17.0+ds1-2ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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
	exit( 0 );
}
exit( 0 );


if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843958" );
	script_version( "2021-08-31T11:01:29+0000" );
	script_cve_id( "CVE-2018-1000100", "CVE-2018-13005", "CVE-2018-13006", "CVE-2018-20760", "CVE-2018-20761", "CVE-2018-20762", "CVE-2018-20763", "CVE-2018-7752" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 11:01:29 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-29 18:57:00 +0000 (Fri, 29 Mar 2019)" );
	script_tag( name: "creation_date", value: "2019-04-03 06:40:31 +0000 (Wed, 03 Apr 2019)" );
	script_name( "Ubuntu Update for gpac USN-3926-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.04 LTS|UBUNTU18\\.10|UBUNTU16\\.04 LTS)" );
	script_xref( name: "USN", value: "3926-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3926-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gpac'
  package(s) announced via the USN-3926-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that the GPAC MP4Box
utility incorrectly handled certain memory operations. If an user or automated
system were tricked into opening a specially crafted MP4 file, a remote attacker
could use this issue to cause MP4Box to crash, resulting in a denial of service,
or possibly execute arbitrary code." );
	script_tag( name: "affected", value: "'gpac' package(s) on Ubuntu 18.10, Ubuntu 18.04 LTS, Ubuntu 16.04 LTS." );
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "gpac", ver: "0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gpac-modules-base", ver: "0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgpac4", ver: "0.5.2-426-gc5ad4e4+dfsg5-3ubuntu0.1", rls: "UBUNTU18.04 LTS" ) )){
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "gpac", ver: "0.5.2-426-gc5ad4e4+dfsg5-4ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gpac-modules-base", ver: "0.5.2-426-gc5ad4e4+dfsg5-4ubuntu0.1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgpac4", ver: "0.5.2-426-gc5ad4e4+dfsg5-4ubuntu0.1", rls: "UBUNTU18.10" ) )){
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
	if(!isnull( res = isdpkgvuln( pkg: "gpac", ver: "0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "gpac-modules-base", ver: "0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libgpac4", ver: "0.5.2-426-gc5ad4e4+dfsg5-1ubuntu0.1", rls: "UBUNTU16.04 LTS" ) )){
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


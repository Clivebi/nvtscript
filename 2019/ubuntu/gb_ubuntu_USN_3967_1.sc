if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.843995" );
	script_version( "2021-08-31T10:01:32+0000" );
	script_cve_id( "CVE-2018-15822", "CVE-2019-11338", "CVE-2019-11339", "CVE-2019-9718", "CVE-2019-9721" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 10:01:32 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-01-04 19:15:00 +0000 (Mon, 04 Jan 2021)" );
	script_tag( name: "creation_date", value: "2019-05-07 02:00:34 +0000 (Tue, 07 May 2019)" );
	script_name( "Ubuntu Update for ffmpeg USN-3967-1" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Ubuntu Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/ubuntu_linux", "ssh/login/packages",  "ssh/login/release=(UBUNTU18\\.10|UBUNTU19\\.04|UBUNTU18\\.04 LTS)" );
	script_xref( name: "USN", value: "3967-1" );
	script_xref( name: "URL", value: "http://www.ubuntu.com/usn/usn-3967-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ffmpeg'
  package(s) announced via the USN-3967-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "It was discovered that FFmpeg contained multiple security issues when
handling
certain multimedia files. If a user were tricked into opening a crafted
multimedia file, an attacker could cause a denial of service via
application
crash." );
	script_tag( name: "affected", value: "'ffmpeg' package(s) on Ubuntu 19.04, Ubuntu 18.10, Ubuntu 18.04 LTS." );
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
if(release == "UBUNTU18.10"){
	if(!isnull( res = isdpkgvuln( pkg: "ffmpeg", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra58", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec58", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavdevice58", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter-extra7", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter7", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavformat58", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavresample4", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavutil56", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpostproc55", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswresample3", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswscale5", ver: "7:4.0.4-0ubuntu1", rls: "UBUNTU18.10" ) )){
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
if(release == "UBUNTU19.04"){
	if(!isnull( res = isdpkgvuln( pkg: "ffmpeg", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra58", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec58", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavdevice58", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter-extra7", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter7", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavformat58", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavresample4", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavutil56", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpostproc55", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswresample3", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswscale5", ver: "7:4.1.3-0ubuntu1", rls: "UBUNTU19.04" ) )){
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
if(release == "UBUNTU18.04 LTS"){
	if(!isnull( res = isdpkgvuln( pkg: "ffmpeg", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec-extra57", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavcodec57", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavdevice57", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter-extra6", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavfilter6", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavformat57", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavresample3", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libavutil55", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libpostproc54", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswresample2", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
		report += res;
	}
	if(!isnull( res = isdpkgvuln( pkg: "libswscale4", ver: "7:3.4.6-0ubuntu0.18.04.1", rls: "UBUNTU18.04 LTS" ) )){
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


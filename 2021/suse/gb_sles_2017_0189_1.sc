if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0189.1" );
	script_cve_id( "CVE-2016-9811" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0189-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0189-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170189-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-plugins-base' package(s) announced via the SUSE-SU-2017:0189-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "* CVE-2016-9811: out of bound memory read could lead to crash
 [bsc#1013669]." );
	script_tag( name: "affected", value: "'gstreamer-plugins-base' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP2, SUSE Linux Enterprise Workstation Extension 12-SP1." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base", rpm: "gstreamer-plugins-base~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-debuginfo", rpm: "gstreamer-plugins-base-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-debuginfo-32bit", rpm: "gstreamer-plugins-base-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-debugsource", rpm: "gstreamer-plugins-base-debugsource~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gstreamer-plugins-base-lang", rpm: "gstreamer-plugins-base-lang~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0", rpm: "libgstallocators-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstallocators-1_0-0-debuginfo", rpm: "libgstallocators-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0", rpm: "libgstapp-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-32bit", rpm: "libgstapp-1_0-0-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-debuginfo", rpm: "libgstapp-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstapp-1_0-0-debuginfo-32bit", rpm: "libgstapp-1_0-0-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0", rpm: "libgstaudio-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-32bit", rpm: "libgstaudio-1_0-0-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-debuginfo", rpm: "libgstaudio-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstaudio-1_0-0-debuginfo-32bit", rpm: "libgstaudio-1_0-0-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0", rpm: "libgstfft-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstfft-1_0-0-debuginfo", rpm: "libgstfft-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0", rpm: "libgstpbutils-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-32bit", rpm: "libgstpbutils-1_0-0-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-debuginfo", rpm: "libgstpbutils-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstpbutils-1_0-0-debuginfo-32bit", rpm: "libgstpbutils-1_0-0-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0", rpm: "libgstriff-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstriff-1_0-0-debuginfo", rpm: "libgstriff-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0", rpm: "libgstrtp-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtp-1_0-0-debuginfo", rpm: "libgstrtp-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0", rpm: "libgstrtsp-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstrtsp-1_0-0-debuginfo", rpm: "libgstrtsp-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0", rpm: "libgstsdp-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstsdp-1_0-0-debuginfo", rpm: "libgstsdp-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0", rpm: "libgsttag-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-32bit", rpm: "libgsttag-1_0-0-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-debuginfo", rpm: "libgsttag-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgsttag-1_0-0-debuginfo-32bit", rpm: "libgsttag-1_0-0-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0", rpm: "libgstvideo-1_0-0~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-32bit", rpm: "libgstvideo-1_0-0-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-debuginfo", rpm: "libgstvideo-1_0-0-debuginfo~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgstvideo-1_0-0-debuginfo-32bit", rpm: "libgstvideo-1_0-0-debuginfo-32bit~1.2.4~2.3.2", rls: "SLES12.0SP1" ) )){
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


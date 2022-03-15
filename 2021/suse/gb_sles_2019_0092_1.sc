if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0092.1" );
	script_cve_id( "CVE-2018-11713", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165", "CVE-2018-4191", "CVE-2018-4197", "CVE-2018-4207", "CVE-2018-4208", "CVE-2018-4209", "CVE-2018-4210", "CVE-2018-4212", "CVE-2018-4213", "CVE-2018-4299", "CVE-2018-4306", "CVE-2018-4309", "CVE-2018-4312", "CVE-2018-4314", "CVE-2018-4315", "CVE-2018-4316", "CVE-2018-4317", "CVE-2018-4318", "CVE-2018-4319", "CVE-2018-4323", "CVE-2018-4328", "CVE-2018-4345", "CVE-2018-4358", "CVE-2018-4359", "CVE-2018-4361", "CVE-2018-4372", "CVE-2018-4373", "CVE-2018-4375", "CVE-2018-4376", "CVE-2018-4378", "CVE-2018-4382", "CVE-2018-4386", "CVE-2018-4392", "CVE-2018-4416", "CVE-2018-4437", "CVE-2018-4438", "CVE-2018-4441", "CVE-2018-4442", "CVE-2018-4443", "CVE-2018-4464" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:32 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-14 23:15:00 +0000 (Fri, 14 Aug 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0092-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0092-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190092-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2019:0092-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.22.5 fixes the following issues:

Security issues fixed:
CVE-2018-4372, CVE-2018-4345, CVE-2018-4386, CVE-2018-4375,
 CVE-2018-4376, CVE-2018-4378, CVE-2018-4382, CVE-2018-4392,
 CVE-2018-4416, CVE-2018-4191, CVE-2018-4197, CVE-2018-4299,
 CVE-2018-4306, CVE-2018-4309, CVE-2018-4312, CVE-2018-4314,
 CVE-2018-4315, CVE-2018-4316, CVE-2018-4317, CVE-2018-4318,
 CVE-2018-4319, CVE-2018-4323, CVE-2018-4328, CVE-2018-4358,
 CVE-2018-4359, CVE-2018-4361, CVE-2018-4373, CVE-2018-4162,
 CVE-2018-4163, CVE-2018-4165, CVE-2018-11713, CVE-2018-4207,
 CVE-2018-4208, CVE-2018-4209, CVE-2018-4210, CVE-2018-4212,
 CVE-2018-4213, CVE-2018-4437, CVE-2018-4438, CVE-2018-4441,
 CVE-2018-4442, CVE-2018-4443, CVE-2018-4464 (bsc#1119558, bsc#1116998,
 bsc#1110279)" );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15." );
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk3-lang", rpm: "libwebkit2gtk3-lang~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2WebExtension-4_0", rpm: "typelib-1_0-WebKit2WebExtension-4_0~2.22.5~3.13.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-devel", rpm: "webkit2gtk3-devel~2.22.5~3.13.1", rls: "SLES15.0" ) )){
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


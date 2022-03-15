if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.3387.1" );
	script_cve_id( "CVE-2017-13884", "CVE-2017-13885", "CVE-2017-7153", "CVE-2017-7160", "CVE-2017-7161", "CVE-2017-7165", "CVE-2018-11646", "CVE-2018-11712", "CVE-2018-11713", "CVE-2018-12911", "CVE-2018-4088", "CVE-2018-4096", "CVE-2018-4101", "CVE-2018-4113", "CVE-2018-4114", "CVE-2018-4117", "CVE-2018-4118", "CVE-2018-4119", "CVE-2018-4120", "CVE-2018-4121", "CVE-2018-4122", "CVE-2018-4125", "CVE-2018-4127", "CVE-2018-4128", "CVE-2018-4129", "CVE-2018-4133", "CVE-2018-4146", "CVE-2018-4161", "CVE-2018-4162", "CVE-2018-4163", "CVE-2018-4165", "CVE-2018-4190", "CVE-2018-4199", "CVE-2018-4200", "CVE-2018-4204", "CVE-2018-4218", "CVE-2018-4222", "CVE-2018-4232", "CVE-2018-4233", "CVE-2018-4246" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-09-18 14:58:00 +0000 (Tue, 18 Sep 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:3387-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:3387-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20183387-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3' package(s) announced via the SUSE-SU-2018:3387-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for webkit2gtk3 to version 2.20.3 fixes the issues:

The following security vulnerabilities were addressed:
CVE-2018-12911: Fixed an off-by-one error in xdg_mime_get_simple_globs
 (boo#1101999)

CVE-2017-13884: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2017-13885: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2017-7153: An unspecified issue allowed remote attackers to spoof
 user-interface information (about whether the entire content is derived
 from a valid TLS session) via a crafted web site that sends a 401
 Unauthorized redirect (bsc#1077535).

CVE-2017-7160: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2017-7161: An unspecified issue allowed remote attackers to execute
 arbitrary code via special characters that trigger command injection
 (bsc#1075775, bsc#1077535).

CVE-2017-7165: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2018-4088: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2018-4096: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1075775).

CVE-2018-4200: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site that triggers a
 WebCore::jsElementScrollHeightGetter use-after-free (bsc#1092280).

CVE-2018-4204: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1092279).

CVE-2018-4101: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1088182).

CVE-2018-4113: An issue in the JavaScriptCore function in the 'WebKit'
 component allowed attackers to trigger an assertion failure by
 leveraging improper array indexing (bsc#1088182)

CVE-2018-4114: An unspecified issue allowed remote attackers to execute
 arbitrary code or cause a denial of service (memory corruption and
 application crash) via a crafted web site (bsc#1088182)

CVE-2018-4117: An unspecified issue allowed ... [Please see the references for more information on the vulnerabilities]" );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on SUSE Linux Enterprise Desktop 12-SP3, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Software Development Kit 12-SP3, SUSE Linux Enterprise Workstation Extension 12-SP3." );
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18", rpm: "libjavascriptcoregtk-4_0-18~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjavascriptcoregtk-4_0-18-debuginfo", rpm: "libjavascriptcoregtk-4_0-18-debuginfo~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37", rpm: "libwebkit2gtk-4_0-37~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwebkit2gtk-4_0-37-debuginfo", rpm: "libwebkit2gtk-4_0-37-debuginfo~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-JavaScriptCore-4_0", rpm: "typelib-1_0-JavaScriptCore-4_0~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-WebKit2-4_0", rpm: "typelib-1_0-WebKit2-4_0~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles", rpm: "webkit2gtk-4_0-injected-bundles~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk-4_0-injected-bundles-debuginfo", rpm: "webkit2gtk-4_0-injected-bundles-debuginfo~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3-debugsource", rpm: "webkit2gtk3-debugsource~2.20.3~2.23.8", rls: "SLES12.0SP3" ) )){
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


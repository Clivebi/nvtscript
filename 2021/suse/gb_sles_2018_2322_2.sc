if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.2322.2" );
	script_cve_id( "CVE-2018-12359", "CVE-2018-12360", "CVE-2018-12362", "CVE-2018-12363", "CVE-2018-12364", "CVE-2018-12365", "CVE-2018-12366", "CVE-2018-12368", "CVE-2018-5156", "CVE-2018-5188" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 18:39:00 +0000 (Thu, 06 Dec 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:2322-2)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:2322-2" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20182322-2/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'MozillaFirefox' package(s) announced via the SUSE-SU-2018:2322-2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for MozillaFirefox to version ESR 52.9 fixes the following issues:
CVE-2018-5188: Various memory safety bugs (bsc#1098998)

CVE-2018-12368: No warning when opening executable SettingContent-ms
 files

CVE-2018-12366: Invalid data handling during QCMS transformations

CVE-2018-12365: Compromised IPC child process can list local filenames

CVE-2018-12364: CSRF attacks through 307 redirects and NPAPI plugins

CVE-2018-12363: Use-after-free when appending DOM nodes

CVE-2018-12362: Integer overflow in SSSE3 scaler

CVE-2018-12360: Use-after-free when using focus()

CVE-2018-5156: Media recorder segmentation fault when track type is
 changed during capture

CVE-2018-12359: Buffer overflow using computed size of canvas element" );
	script_tag( name: "affected", value: "'MozillaFirefox' package(s) on SUSE Linux Enterprise Server 12-SP2." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox", rpm: "MozillaFirefox~52.9.0esr~109.38.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debuginfo", rpm: "MozillaFirefox-debuginfo~52.9.0esr~109.38.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-debugsource", rpm: "MozillaFirefox-debugsource~52.9.0esr~109.38.2", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "MozillaFirefox-devel", rpm: "MozillaFirefox-devel~52.9.0esr~109.38.2", rls: "SLES12.0SP2" ) )){
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


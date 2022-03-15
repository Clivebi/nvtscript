if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.2065.1" );
	script_cve_id( "CVE-2015-0794" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-05 19:06:00 +0000 (Mon, 05 Oct 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:2065-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:2065-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20152065-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'dracut' package(s) announced via the SUSE-SU-2015:2065-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The dracut package was updated to fix the following security and non-security issues:
- CVE-2015-0794: Use mktemp instead of hardcoded filenames, possible
 vulnerability (bsc#935338).
- Always install mdraid modules (bsc#935993).
- Add notice when dracut failed to install modules (bsc#952491).
- Always install dm-snaphost module if lvm dracut module is needed, even
 if dm-snapshot is not loaded on the host yet (bsc#947518)." );
	script_tag( name: "affected", value: "'dracut' package(s) on SUSE Linux Enterprise Desktop 12, SUSE Linux Enterprise Server 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "dracut", rpm: "dracut~037~51.17.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dracut-debuginfo", rpm: "dracut-debuginfo~037~51.17.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dracut-debugsource", rpm: "dracut-debugsource~037~51.17.3", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "dracut-fips", rpm: "dracut-fips~037~51.17.3", rls: "SLES12.0" ) )){
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


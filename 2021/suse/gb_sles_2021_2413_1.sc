if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2413.1" );
	script_cve_id( "CVE-2021-32760" );
	script_tag( name: "creation_date", value: "2021-07-21 06:49:19 +0000 (Wed, 21 Jul 2021)" );
	script_version( "2021-08-14T02:23:29+0000" );
	script_tag( name: "last_modification", value: "2021-08-14 02:23:29 +0000 (Sat, 14 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-28 17:31:00 +0000 (Wed, 28 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2413-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2413-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212413-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'containerd' package(s) announced via the SUSE-SU-2021:2413-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for containerd fixes the following issues:

CVE-2021-32760: Fixed a bug which allows untrusted container images to
 change permissions in the host's filesystem. (bsc#1188282)" );
	script_tag( name: "affected", value: "'containerd' package(s) on SUSE Linux Enterprise Module for Containers 12." );
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
	if(!isnull( res = isrpmvuln( pkg: "containerd", rpm: "containerd~1.4.4~16.42.1", rls: "SLES12.0" ) )){
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


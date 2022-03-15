if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.3244.1" );
	script_tag( name: "creation_date", value: "2021-09-29 06:41:19 +0000 (Wed, 29 Sep 2021)" );
	script_version( "2021-09-29T06:41:19+0000" );
	script_tag( name: "last_modification", value: "2021-09-29 06:41:19 +0000 (Wed, 29 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-09-29 06:41:02 +0000 (Wed, 29 Sep 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:3244-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:3244-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20213244-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'shibboleth-sp' package(s) announced via the SUSE-SU-2021:3244-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for shibboleth-sp fixes the following issues:

Template generation allows external parameters to override placeholders
 (bsc#1184222)" );
	script_tag( name: "affected", value: "'shibboleth-sp' package(s) on SUSE Linux Enterprise Module for Server Applications 15-SP3." );
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite8", rpm: "libshibsp-lite8~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp-lite8-debuginfo", rpm: "libshibsp-lite8-debuginfo~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp9", rpm: "libshibsp9~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libshibsp9-debuginfo", rpm: "libshibsp9-debuginfo~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp", rpm: "shibboleth-sp~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debuginfo", rpm: "shibboleth-sp-debuginfo~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-debugsource", rpm: "shibboleth-sp-debugsource~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "shibboleth-sp-devel", rpm: "shibboleth-sp-devel~3.1.0~3.3.1", rls: "SLES15.0SP3" ) )){
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


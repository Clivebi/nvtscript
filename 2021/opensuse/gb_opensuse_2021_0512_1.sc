if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.853620" );
	script_version( "2021-04-21T07:29:02+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-04-21 07:29:02 +0000 (Wed, 21 Apr 2021)" );
	script_tag( name: "creation_date", value: "2021-04-16 04:57:05 +0000 (Fri, 16 Apr 2021)" );
	script_name( "openSUSE: Security Advisory for OpenIPMI (openSUSE-SU-2021:0512-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse", "ssh/login/rpms",  "ssh/login/release=openSUSELeap15\\.2" );
	script_xref( name: "Advisory-ID", value: "openSUSE-SU-2021:0512-1" );
	script_xref( name: "URL", value: "https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/QXDY6TSSKHQSEJCJX5L6BHK44JP2GR6G" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenIPMI'
  package(s) announced via the openSUSE-SU-2021:0512-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for OpenIPMI fixes the following issues:

  - Fixed an issue where OpenIPMI was creating non-position independent
       binaries (bsc#1183178).

     This update was imported from the SUSE:SLE-15-SP1:Update update project." );
	script_tag( name: "affected", value: "'OpenIPMI' package(s) on openSUSE Leap 15.2." );
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
if(release == "openSUSELeap15.2"){
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI", rpm: "OpenIPMI~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI-debuginfo", rpm: "OpenIPMI-debuginfo~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI-debugsource", rpm: "OpenIPMI-debugsource~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI-devel", rpm: "OpenIPMI-devel~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI-python", rpm: "OpenIPMI-python~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "OpenIPMI-python-debuginfo", rpm: "OpenIPMI-python-debuginfo~2.0.25~lp152.3.3.1", rls: "openSUSELeap15.2" ) )){
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


if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2019.0285.1" );
	script_cve_id( "CVE-2018-1000845" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:31 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "Greenbone" );
	script_tag( name: "severity_date", value: "2021-06-09 15:01:51 +0000 (Wed, 09 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2019:0285-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2019:0285-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2019/suse-su-20190285-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'avahi' package(s) announced via the SUSE-SU-2019:0285-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for avahi fixes the following issues:

Security issue fixed:
CVE-2018-1000845: Fixed DNS amplification and reflection to spoofed
 addresses (DOS) (bsc#1120281)" );
	script_tag( name: "affected", value: "'avahi' package(s) on SUSE Linux Enterprise Module for Basesystem 15, SUSE Linux Enterprise Module for Desktop Applications 15, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15, SUSE Linux Enterprise Module for Packagehub Subpackages 15." );
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
	if(!isnull( res = isrpmvuln( pkg: "avahi", rpm: "avahi~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-compat-howl-devel", rpm: "avahi-compat-howl-devel~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-compat-mDNSResponder-devel", rpm: "avahi-compat-mDNSResponder-devel~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debuginfo", rpm: "avahi-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-debugsource", rpm: "avahi-debugsource~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-glib2-debugsource", rpm: "avahi-glib2-debugsource~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-lang", rpm: "avahi-lang~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils", rpm: "avahi-utils~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils-debuginfo", rpm: "avahi-utils-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3", rpm: "libavahi-client3~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-debuginfo", rpm: "libavahi-client3-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3", rpm: "libavahi-common3~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-debuginfo", rpm: "libavahi-common3-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7", rpm: "libavahi-core7~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-core7-debuginfo", rpm: "libavahi-core7-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-devel", rpm: "libavahi-devel~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib-devel", rpm: "libavahi-glib-devel~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1", rpm: "libavahi-glib1~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-glib1-debuginfo", rpm: "libavahi-glib1-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-gobject0", rpm: "libavahi-gobject0~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-gobject0-debuginfo", rpm: "libavahi-gobject0-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-ui-gtk3-0", rpm: "libavahi-ui-gtk3-0~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-ui-gtk3-0-debuginfo", rpm: "libavahi-ui-gtk3-0-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-ui0", rpm: "libavahi-ui0~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-ui0-debuginfo", rpm: "libavahi-ui0-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd", rpm: "libdns_sd~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libdns_sd-debuginfo", rpm: "libdns_sd-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhowl0", rpm: "libhowl0~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libhowl0-debuginfo", rpm: "libhowl0-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "typelib-1_0-Avahi-0_6", rpm: "typelib-1_0-Avahi-0_6~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-32bit-debuginfo", rpm: "avahi-32bit-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-autoipd", rpm: "avahi-autoipd~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-autoipd-debuginfo", rpm: "avahi-autoipd-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils-gtk", rpm: "avahi-utils-gtk~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "avahi-utils-gtk-debuginfo", rpm: "avahi-utils-gtk-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-32bit", rpm: "libavahi-client3-32bit~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-client3-32bit-debuginfo", rpm: "libavahi-client3-32bit-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-32bit", rpm: "libavahi-common3-32bit~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-common3-32bit-debuginfo", rpm: "libavahi-common3-32bit-debuginfo~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libavahi-gobject-devel", rpm: "libavahi-gobject-devel~0.6.32~5.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "python-avahi", rpm: "python-avahi~0.6.32~5.3.1", rls: "SLES15.0" ) )){
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

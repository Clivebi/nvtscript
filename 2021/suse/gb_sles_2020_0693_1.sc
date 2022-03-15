if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.0693.1" );
	script_cve_id( "CVE-2018-11354", "CVE-2018-11355", "CVE-2018-11356", "CVE-2018-11357", "CVE-2018-11358", "CVE-2018-11359", "CVE-2018-11360", "CVE-2018-11361", "CVE-2018-11362", "CVE-2018-12086", "CVE-2018-14339", "CVE-2018-14340", "CVE-2018-14341", "CVE-2018-14342", "CVE-2018-14343", "CVE-2018-14344", "CVE-2018-14367", "CVE-2018-14368", "CVE-2018-14369", "CVE-2018-14370", "CVE-2018-16056", "CVE-2018-16057", "CVE-2018-16058", "CVE-2018-18225", "CVE-2018-18226", "CVE-2018-18227", "CVE-2018-19622", "CVE-2018-19623", "CVE-2018-19624", "CVE-2018-19625", "CVE-2018-19626", "CVE-2018-19627", "CVE-2018-19628", "CVE-2019-10894", "CVE-2019-10895", "CVE-2019-10896", "CVE-2019-10897", "CVE-2019-10898", "CVE-2019-10899", "CVE-2019-10900", "CVE-2019-10901", "CVE-2019-10902", "CVE-2019-10903", "CVE-2019-13619", "CVE-2019-16319", "CVE-2019-19553", "CVE-2019-5716", "CVE-2019-5717", "CVE-2019-5718", "CVE-2019-5719", "CVE-2019-5721", "CVE-2019-9208", "CVE-2019-9209", "CVE-2019-9214", "CVE-2020-7044", "CVE-2020-9428", "CVE-2020-9429", "CVE-2020-9430", "CVE-2020-9431" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-20 01:15:00 +0000 (Fri, 20 Mar 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:0693-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:0693-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20200693-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'wireshark' package(s) announced via the SUSE-SU-2020:0693-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for wireshark and libmaxminddb fixes the following issues:

Update wireshark to new major version 3.2.2 and introduce libmaxminddb for GeoIP support (bsc#1156288).

New features include:
Added support for 111 new protocols, including WireGuard, LoRaWAN, TPM
 2.0, 802.11ax and QUIC

Improved support for existing protocols, like HTTP/2

Improved analytics and usability functionalities" );
	script_tag( name: "affected", value: "'wireshark' package(s) on SUSE Linux Enterprise High Performance Computing 15, SUSE Linux Enterprise Module for Basesystem 15-SP1, SUSE Linux Enterprise Module for Desktop Applications 15-SP1, SUSE Linux Enterprise Module for Open Buildservice Development Tools 15-SP1, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb-debugsource", rpm: "libmaxminddb-debugsource~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb-devel", rpm: "libmaxminddb-devel~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0", rpm: "libmaxminddb0~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0-32bit", rpm: "libmaxminddb0-32bit~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0-32bit-debuginfo", rpm: "libmaxminddb0-32bit-debuginfo~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0-debuginfo", rpm: "libmaxminddb0-debuginfo~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspandsp2", rpm: "libspandsp2~0.0.6~3.2.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspandsp2-debuginfo", rpm: "libspandsp2-debuginfo~0.0.6~3.2.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark13", rpm: "libwireshark13~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark13-debuginfo", rpm: "libwireshark13-debuginfo~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap10", rpm: "libwiretap10~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap10-debuginfo", rpm: "libwiretap10-debuginfo~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil11", rpm: "libwsutil11~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil11-debuginfo", rpm: "libwsutil11-debuginfo~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mmdblookup", rpm: "mmdblookup~1.4.2~1.3.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spandsp-debugsource", rpm: "spandsp-debugsource~0.0.6~3.2.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "spandsp-devel", rpm: "spandsp-devel~0.0.6~3.2.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-devel", rpm: "wireshark-devel~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-ui-qt", rpm: "wireshark-ui-qt~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-ui-qt-debuginfo", rpm: "wireshark-ui-qt-debuginfo~3.2.2~3.35.2", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb-debugsource", rpm: "libmaxminddb-debugsource~1.4.2~1.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb-devel", rpm: "libmaxminddb-devel~1.4.2~1.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0", rpm: "libmaxminddb0~1.4.2~1.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libmaxminddb0-debuginfo", rpm: "libmaxminddb0-debuginfo~1.4.2~1.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspandsp2", rpm: "libspandsp2~0.0.6~3.2.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libspandsp2-debuginfo", rpm: "libspandsp2-debuginfo~0.0.6~3.2.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark13", rpm: "libwireshark13~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwireshark13-debuginfo", rpm: "libwireshark13-debuginfo~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap10", rpm: "libwiretap10~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwiretap10-debuginfo", rpm: "libwiretap10-debuginfo~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil11", rpm: "libwsutil11~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libwsutil11-debuginfo", rpm: "libwsutil11-debuginfo~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "mmdblookup", rpm: "mmdblookup~1.4.2~1.3.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark", rpm: "wireshark~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debuginfo", rpm: "wireshark-debuginfo~3.2.2~3.35.2", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "wireshark-debugsource", rpm: "wireshark-debugsource~3.2.2~3.35.2", rls: "SLES15.0" ) )){
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


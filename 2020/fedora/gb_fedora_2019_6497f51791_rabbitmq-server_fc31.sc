if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.877264" );
	script_version( "2021-07-20T11:00:49+0000" );
	script_cve_id( "CVE-2019-11281", "CVE-2019-11287" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-07-20 11:00:49 +0000 (Tue, 20 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:14:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-01-09 07:34:45 +0000 (Thu, 09 Jan 2020)" );
	script_name( "Fedora Update for rabbitmq-server FEDORA-2019-6497f51791" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC31" );
	script_xref( name: "FEDORA", value: "2019-6497f51791" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EEQ6O7PMNJKYFMQYHAB55L423GYK63SO" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rabbitmq-server'
  package(s) announced via the FEDORA-2019-6497f51791 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "RabbitMQ is an implementation of AMQP, the emerging standard for high
performance enterprise messaging. The RabbitMQ server is a robust and
scalable implementation of an AMQP broker." );
	script_tag( name: "affected", value: "'rabbitmq-server' package(s) on Fedora 31." );
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
if(release == "FC31"){
	if(!isnull( res = isrpmvuln( pkg: "rabbitmq-server", rpm: "rabbitmq-server~3.7.22~1.fc31", rls: "FC31" ) )){
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


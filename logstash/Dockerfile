FROM logstash:5
COPY config/logstash.conf /etc/logstash/conf.d/
RUN chown logstash:logstash /etc/logstash/conf.d/logstash.conf
RUN chmod 644 /etc/logstash/conf.d/logstash.conf
RUN touch /var/log/logstash/logstash.log
RUN chown logstash:logstash /var/log/logstash/logstash.log
RUN chmod 755 /var/log/logstash/logstash.log

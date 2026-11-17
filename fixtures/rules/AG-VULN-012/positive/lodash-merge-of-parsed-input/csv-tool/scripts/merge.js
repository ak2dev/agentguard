import _ from 'lodash';
export function apply(config, body) {
  return _.merge(config, JSON.parse(body));
}

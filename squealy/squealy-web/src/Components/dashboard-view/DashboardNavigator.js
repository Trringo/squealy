import React, {Component} from 'react'
import {Tabs, Tab} from 'react-bootstrap'
import Dashboard from './Dashboard'
import {HidashModal} from '../HidashUtilsComponents'


export default class DashboardNavigator extends Component {
  constructor() {
    super()
  }

  handleSelect = (key, e) => {
    if (key === 'add_tab') {
      this.props.dashboardAdditionHandler()
    }
    else {
        this.props.selectDashboard(key)
    }
  }
  
  render() {
    const {dashboardDefinition, widgetAdditionHandler, selectedDashboardIndex} = this.props

      const dashboard_tabs = dashboardDefinition.map((dashboard, i)=>{
        return (
          <Tab
            key={i}
            title={'Dashboard-'+i}
            eventKey={i}
          >
            <div className="panel panel-default">
              <div className="panel-body">
                <Dashboard dashboardDefinition={dashboard}
                widgetAdditionHandler={widgetAdditionHandler}
                dashboardIndex={i}
                />
              </div>
            </div>
           </Tab>
        )
      })

    return(
        <Tabs
        bsStyle="tabs"
        animation={true}
        activeKey={selectedDashboardIndex}
        onSelect={this.handleSelect}
        id='dashboard-tabs'
         >
        {dashboard_tabs}
        <Tab id='add_tab_btn'
          style={{
            borderColor: '#fff'
            }}
          title={
            <div id="tabPlusIconWrapper">
              <i className="fa fa-plus tab-plus-icon" />&nbsp;
            </div>}
          eventKey="add_tab"
        />
      </Tabs>
    )
  }
}
